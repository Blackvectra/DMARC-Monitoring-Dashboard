namespace DmarcMonitor.Core.Aggregate;

/// <summary>
/// Which of a receiver's policy-override reasons excuse an authentication
/// failure, and the one way every query asks.
/// </summary>
/// <remarks>
/// <para>
/// A receiver writes a reason beside a record when what it did differs from
/// what the domain's policy asked for, and the reasons are not alike. Four say
/// the failure was expected. <c>forwarded</c>, <c>trusted_forwarder</c> and
/// <c>mailing_list</c> name a path that breaks authentication as a matter of
/// course, and <c>local_policy</c> says the receiver chose to deliver the
/// message anyway. Those failures are left out of the tables of sources to act
/// on, because a mailing list breaking a signature would otherwise bury
/// everything worth reading.
/// </para>
/// <para>
/// The others excuse nothing. <c>sampled_out</c> says the message escaped the
/// policy because of <c>pct</c>: a forgery that only got through because the
/// domain has not finished tightening, which is exactly what somebody ramping
/// <c>pct</c> has to keep seeing. <c>other</c> says the receiver had a reason
/// it did not give, and <c>Unknown</c> is a value nobody recognizes. One
/// receiver sends <c>other</c> beside a message it quarantined under
/// <c>p=quarantine</c> - the policy applied as published, for a message signed
/// with a random selector on the victim's domain, from a home broadband
/// address on another continent - and every page and the command line called
/// it a forwarder or mailing list and said to ignore it.
/// </para>
/// <para>
/// The stored column keeps every reason as received. What a reason excuses is
/// decided here, at read time, so a change to this rule applies to what is
/// already stored as well as to what comes in.
/// </para>
/// </remarks>
public static class PolicyOverrides
{
    /// <summary>True when the receiver is saying this failure was expected.</summary>
    public static bool Excuses(OverrideReason reason) =>
        reason is OverrideReason.Forwarded
            or OverrideReason.TrustedForwarder
            or OverrideReason.MailingList
            or OverrideReason.LocalPolicy;

    /// <summary>
    /// How a reason is written into <c>aggregate_records.override_reason</c>:
    /// the enum's name in lower case, with no underscore. Several reasons on
    /// one record are joined with a semicolon.
    /// </summary>
    /// <remarks>
    /// One place decides the spelling, and the queries below are built from it.
    /// A query that wrote <c>'sampled_out'</c> by hand matched nothing for as
    /// long as it existed, because this is stored as <c>sampledout</c>.
    /// </remarks>
    public static string Stored(OverrideReason reason) => reason.ToString().ToLowerInvariant();

    /// <summary>
    /// A SQL condition that is true when the row carries a reason that excuses
    /// it, and false - never null - when it carries none or only reasons that
    /// do not.
    /// </summary>
    /// <param name="alias">
    /// The alias of the <c>aggregate_records</c> table in the query, or empty
    /// where the column is not qualified.
    /// </param>
    public static string ExcusedSql(string alias = "")
    {
        var column = string.IsNullOrEmpty(alias) ? "override_reason" : $"{alias}.override_reason";

        var tests = string.Join(
            " OR ",
            Enum.GetValues<OverrideReason>()
                .Where(Excuses)
                .Select(r => $"instr(';' || {column} || ';', ';{Stored(r)};') > 0"));

        // The first test is what keeps the whole condition from being null on
        // a row with no reason, which is most of them: NOT of null is null and
        // would drop the row from a query that meant to keep it.
        return $"(COALESCE({column}, '') <> '' AND ({tests}))";
    }
}
