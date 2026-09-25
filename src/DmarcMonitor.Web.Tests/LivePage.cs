using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

// BL0006 warns off the render-tree types outside the framework, because their
// shape can change between releases. A renderer is what they exist for, and
// this one is test code: if a release moves them, this file breaks, loudly,
// and nothing that ships does.
#pragma warning disable BL0006

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// One page, rendered the way a live circuit renders it, with its controls
/// there to be used.
/// </summary>
/// <remarks>
/// <para>
/// Every other test here asks for a page over HTTP, which is the prerender:
/// the page loads once and its HTML comes back. What a person does next -
/// choose another month, press "Check again" - never happens there, so a page
/// that breaks on the second thing somebody does passes all of them.
/// </para>
/// <para>
/// This is the same kind of renderer the server runs a circuit with, on the
/// application's own services, cut down to what a test needs: render one
/// page, read what it shows, and send the events its buttons and selects
/// would. Text is written as it is rather than HTML-encoded, so an assertion
/// is about what a person reads.
/// </para>
/// <para>
/// The page alone, with no layout around it. What a layout decides - such as
/// whether the page is drawn for this person at all - is asked over HTTP,
/// where the layouts run.
/// </para>
/// </remarks>
internal sealed partial class LivePage : IAsyncDisposable
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(15);

    private readonly AsyncServiceScope _scope;
    private readonly Host _host;

    private LivePage(AsyncServiceScope scope, Host host)
    {
        _scope = scope;
        _host = host;
    }

    /// <summary>Somebody signed in. On an install with no sign-in, that is a master.</summary>
    public static ClaimsPrincipal Operator { get; } =
        new(new ClaimsIdentity([new Claim(ClaimTypes.Name, "operator@example.com")], "Test"));

    /// <summary>Renders a page for a person, and waits for it to finish loading.</summary>
    public static async Task<LivePage> OpenAsync<TPage>(WebApplicationFactory<Program> app, ClaimsPrincipal? user = null)
        where TPage : IComponent
    {
        var scope = app.Services.CreateAsyncScope();

        // Who is looking, the way a circuit is told when it connects.
        if (scope.ServiceProvider.GetRequiredService<AuthenticationStateProvider>()
            is not IHostEnvironmentAuthenticationStateProvider signIn)
        {
            await scope.DisposeAsync();
            throw new InvalidOperationException("The application's sign-in state cannot be set from a test.");
        }

        signIn.SetAuthenticationState(Task.FromResult(new AuthenticationState(user ?? Operator)));

        var host = new Host(scope.ServiceProvider);
        await host.Dispatcher.InvokeAsync(() => host.StartAsync(typeof(TPage)));

        var page = new LivePage(scope, host);
        page.ThrowIfFailed();
        return page;
    }

    /// <summary>What the page shows now.</summary>
    public Task<string> HtmlAsync() => _host.Dispatcher.InvokeAsync(() => _host.Read().Html);

    /// <summary>
    /// Waits for something a page does after it has rendered, such as reading
    /// DNS once it is on screen.
    /// </summary>
    public async Task WaitForAsync(Func<string, bool> condition, string what)
    {
        var deadline = DateTime.UtcNow + Patience;
        while (true)
        {
            ThrowIfFailed();

            var html = await HtmlAsync();
            if (condition(html)) { return; }

            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException($"Waited {Patience.TotalSeconds:0}s for {what}. The page:\n{html}");
            }

            await Task.Delay(25);
        }
    }

    /// <summary>
    /// Presses the one button reading <paramref name="text"/>, or the one in
    /// the section that mentions <paramref name="inSectionWith"/> where a page
    /// has a button per row.
    /// </summary>
    public async Task ClickAsync(string text, string? inSectionWith = null)
    {
        await _host.Dispatcher.InvokeAsync(async () =>
        {
            var tree = _host.Read();
            var buttons = tree.Elements
                .Where(e => e.Name == "button" && e.Handlers.ContainsKey("onclick"))
                .Where(e => e.Text.Trim() == text)
                .Where(e => inSectionWith is null
                    || (e.Nearest("section")?.Text.Contains(inSectionWith, StringComparison.Ordinal) ?? false))
                .ToList();

            if (buttons.Count != 1)
            {
                throw new InvalidOperationException(
                    $"Expected one \"{text}\" button{(inSectionWith is null ? "" : $" beside {inSectionWith}")}, "
                    + $"found {buttons.Count}. The page:\n{tree.Html}");
            }

            await _host.DispatchEventAsync(buttons[0].Handlers["onclick"], null, new MouseEventArgs());
        });

        ThrowIfFailed();
    }

    /// <summary>
    /// Sends the change a browser sends when the select offering
    /// <paramref name="offering"/> is set to <paramref name="value"/>. The value
    /// need not be one of its options: a browser sends whatever the page's
    /// markup has been edited to say.
    /// </summary>
    public async Task ChooseAsync(string offering, string value)
    {
        await _host.Dispatcher.InvokeAsync(async () =>
        {
            var tree = _host.Read();
            var select = Select(tree, offering);
            await _host.DispatchEventAsync(select.Handlers["onchange"], null, new ChangeEventArgs { Value = value });
        });

        ThrowIfFailed();
    }

    /// <summary>What the select offering <paramref name="offering"/> is set to.</summary>
    public Task<string?> ValueOfAsync(string offering) =>
        _host.Dispatcher.InvokeAsync(() => Select(_host.Read(), offering).Attributes.GetValueOrDefault("value"));

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        await _scope.DisposeAsync();
    }

    private static Element Select(Tree tree, string offering) =>
        tree.Elements.SingleOrDefault(e =>
            e.Name == "select"
            && e.Handlers.ContainsKey("onchange")
            && tree.Elements.Any(o => o.Name == "option" && o.Parent == e
                && o.Attributes.GetValueOrDefault("value") == offering))
        ?? throw new InvalidOperationException($"No select offering \"{offering}\". The page:\n{tree.Html}");

    /// <summary>
    /// An exception the page did not handle, raised here rather than lost.
    /// On a real circuit it would have ended the session and left the person
    /// looking at "An unhandled error has occurred".
    /// </summary>
    private void ThrowIfFailed()
    {
        var failures = _host.Failures;
        if (failures.Count > 0)
        {
            throw new AggregateException("The page threw where a circuit would have died.", failures);
        }
    }

    /// <summary>The renderer: a circuit with no browser at the other end.</summary>
    private sealed class Host(IServiceProvider services) : Renderer(services, NullLoggerFactory.Instance)
    {
        private readonly List<Exception> _failures = [];
        private int _root;

        public override Dispatcher Dispatcher { get; } = Dispatcher.CreateDefault();

        protected override RendererInfo RendererInfo { get; } = new("Server", isInteractive: true);

        public IReadOnlyList<Exception> Failures
        {
            get { lock (_failures) { return [.. _failures]; } }
        }

        public Task StartAsync(Type page)
        {
            _root = AssignRootComponentId(InstantiateComponent(page));
            return RenderRootComponentAsync(_root);
        }

        /// <summary>The page as it stands. Only on the dispatcher, where rendering happens.</summary>
        public Tree Read() => Tree.Of(this, _root);

        public ArrayRange<RenderTreeFrame> FramesOf(int componentId) => GetCurrentRenderTreeFrames(componentId);

        // The pages ask for InteractiveServer, and this is the live render of
        // one, so the component is simply made.
        protected override IComponent ResolveComponentForRenderMode(
            Type componentType, int? parentComponentId, IComponentActivator componentActivator,
            IComponentRenderMode renderMode) =>
            componentActivator.CreateInstance(componentType);

        protected override void HandleException(Exception exception)
        {
            lock (_failures) { _failures.Add(exception); }
        }

        // Nothing to send anywhere: what the page shows is read from its
        // render tree when a test asks.
        protected override Task UpdateDisplayAsync(in RenderBatch renderBatch) => Task.CompletedTask;
    }

    /// <summary>The rendered page as markup, and where its controls are.</summary>
    private sealed partial class Tree
    {
        private readonly StringBuilder _html = new();
        private readonly List<Element> _open = [];

        public List<Element> Elements { get; } = [];

        public string Html => _html.ToString();

        public static Tree Of(Host host, int component)
        {
            var tree = new Tree();
            tree.Component(host, component);
            return tree;
        }

        private void Component(Host host, int component)
        {
            var frames = host.FramesOf(component);
            Frames(host, frames, 0, frames.Count);
        }

        private void Frames(Host host, ArrayRange<RenderTreeFrame> frames, int from, int to)
        {
            for (var i = from; i < to;)
            {
                var frame = frames.Array[i];
                switch (frame.FrameType)
                {
                    case RenderTreeFrameType.Element:
                        Element(host, frames, i);
                        i += frame.ElementSubtreeLength;
                        break;

                    case RenderTreeFrameType.Text:
                        Write(frame.TextContent, frame.TextContent);
                        i++;
                        break;

                    // Static markup is compiled into blocks like this one, so
                    // an element with nothing dynamic in it arrives as text.
                    case RenderTreeFrameType.Markup:
                        Write(frame.MarkupContent, Tags().Replace(frame.MarkupContent, ""));
                        i++;
                        break;

                    case RenderTreeFrameType.Component:
                        Component(host, frame.ComponentId);
                        i += frame.ComponentSubtreeLength;
                        break;

                    case RenderTreeFrameType.Region:
                        Frames(host, frames, i + 1, i + frame.RegionSubtreeLength);
                        i += frame.RegionSubtreeLength;
                        break;

                    default:
                        i++;
                        break;
                }
            }
        }

        private void Element(Host host, ArrayRange<RenderTreeFrame> frames, int at)
        {
            var frame = frames.Array[at];
            var end = at + frame.ElementSubtreeLength;
            var element = new Element(frame.ElementName, _open.Count > 0 ? _open[^1] : null);

            _html.Append('<').Append(frame.ElementName);

            var i = at + 1;
            for (; i < end && frames.Array[i].FrameType == RenderTreeFrameType.Attribute; i++)
            {
                var attribute = frames.Array[i];
                if (attribute.AttributeEventHandlerId != 0)
                {
                    element.Handlers[attribute.AttributeName] = attribute.AttributeEventHandlerId;
                    continue;
                }

                element.Attributes[attribute.AttributeName] = attribute.AttributeValue?.ToString() ?? "";
                _html.Append(' ').Append(attribute.AttributeName);

                // A true boolean attribute is written bare; a false one is
                // never in the tree at all.
                if (attribute.AttributeValue is not bool)
                {
                    _html.Append("=\"").Append(attribute.AttributeValue).Append('"');
                }
            }

            _html.Append('>');
            Elements.Add(element);

            _open.Add(element);
            Frames(host, frames, i, end);
            _open.RemoveAt(_open.Count - 1);

            _html.Append("</").Append(frame.ElementName).Append('>');
        }

        private void Write(string markup, string text)
        {
            _html.Append(markup);
            foreach (var element in _open) { element.Append(text); }
        }

        [GeneratedRegex("<[^>]*>")]
        private static partial Regex Tags();
    }

    private sealed class Element(string name, Element? parent)
    {
        private readonly StringBuilder _text = new();

        public string Name { get; } = name;

        public Element? Parent { get; } = parent;

        public Dictionary<string, string> Attributes { get; } = new(StringComparer.Ordinal);

        public Dictionary<string, ulong> Handlers { get; } = new(StringComparer.Ordinal);

        /// <summary>Everything written inside this element, as text.</summary>
        public string Text => _text.ToString();

        public void Append(string text) => _text.Append(text);

        public Element? Nearest(string name)
        {
            for (var e = Parent; e is not null; e = e.Parent)
            {
                if (e.Name == name) { return e; }
            }

            return null;
        }
    }
}
