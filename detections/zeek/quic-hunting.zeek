##! Reference QUIC hunting notices for the quic_research detection lab.
##!
##! Raises one notice per matching connection. Notices are timestamped with
##! the connection's start time, so they line up with conn.log and can be
##! scored against simulator ground truth with `detscore score -notice`.
##!
##! Tune for your environment by redefining the exported constants, e.g.:
##!
##!     redef QUICHunt::long_threshold = 30 min;
##!     redef QUICHunt::approved_nets += { 203.0.113.0/24 };

@load base/frameworks/notice
@load base/protocols/conn

module QUICHunt;

export {
	redef enum Notice::Type += {
		## A QUIC connection lasted at least long_threshold.
		Long_QUIC_Connection,
		## A QUIC connection went to a destination outside approved_nets.
		Unapproved_QUIC_Destination,
	};

	## Duration at which a QUIC connection counts as long-lived.
	const long_threshold = 1 hr &redef;

	## Destinations QUIC is expected to reach. Empty disables the check.
	const approved_nets: set[subnet] = {} &redef;
}

function is_quic(c: connection): bool
	{
	for ( s in c$service )
		{
		if ( to_lower(s) == "quic" )
			return T;
		}
	return F;
	}

event connection_state_remove(c: connection)
	{
	if ( ! is_quic(c) )
		return;

	if ( c$duration >= long_threshold )
		NOTICE([$note=Long_QUIC_Connection, $conn=c, $ts=c$start_time,
		        $msg=fmt("QUIC connection lasted %s", c$duration),
		        $identifier=c$uid]);

	if ( |approved_nets| > 0 && c$id$resp_h !in approved_nets )
		NOTICE([$note=Unapproved_QUIC_Destination, $conn=c, $ts=c$start_time,
		        $msg=fmt("QUIC to %s, outside approved networks", c$id$resp_h),
		        $identifier=c$uid]);
	}
