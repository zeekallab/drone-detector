@load ./tello
@load base/frameworks/cluster

module DroneTello;

export {
	## Broadcasts a confirmed drone/controller pair to every worker, so a
	## worker handling an unrelated UDP flow (e.g. the video stream on
	## 11111) can still satisfy recent_pair() even if it never saw the SDK
	## state messages (port 8890) that originally confirmed the pair.
	##
	## known_pairs is otherwise worker-local: in a Zeek cluster, the state
	## flow and the video flow for the same drone/controller pair can land
	## on different workers, since each UDP 5-tuple is hashed independently.
	global pair_confirmed: event(drone: addr, controller: addr, ts: time);

	## Call this immediately after writing known_pairs[drone,controller].
	## No-op outside a cluster, where a single known_pairs table is already
	## shared by every connection.
	global publish_pair: function(drone: addr, controller: addr, ts: time);
}

@if ( Cluster::is_enabled() )

function publish_pair(drone: addr, controller: addr, ts: time)
	{
	# hrw keeps repeated confirmations of the same pair routed to the same
	# proxy; the proxy then rebroadcasts to every worker below.
	Cluster::publish_hrw(Cluster::proxy_pool, cat(drone, controller),
	                      pair_confirmed, drone, controller, ts);
	}

event pair_confirmed(drone: addr, controller: addr, ts: time)
	{
	if ( Cluster::local_node_type() == Cluster::PROXY )
		Cluster::publish(Cluster::worker_topic(), pair_confirmed, drone, controller, ts);

	if ( Cluster::local_node_type() == Cluster::WORKER )
		known_pairs[drone,controller] = ts;
	}

@else

function publish_pair(drone: addr, controller: addr, ts: time) { }

@endif
