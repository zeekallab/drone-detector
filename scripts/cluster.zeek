@load ./tello
@load base/frameworks/cluster

module DroneTello;

export {
    ## Share initially, then refresh at most once per interval per local pair.
    const pair_publish_interval = 10secs &redef;
    global pair_confirmed: event(drone: addr, controller: addr, ts: time);
}

@if ( Cluster::is_enabled() )

global pair_last_publish: table[addr,addr] of time &write_expire=correlation_age;

hook local_pair_confirmed(drone: addr, controller: addr, ts: time)
    {
    if ( Cluster::local_node_type() != Cluster::WORKER ) return;
    if ( [drone,controller] in pair_last_publish )
        {
        if ( ts-pair_last_publish[drone,controller] < pair_publish_interval ) return;
        }
    else if ( |pair_last_publish| >= max_known_pairs )
        {
        control_tracking_limited_until=network_time()+correlation_age;
        return;
        }
    # Don't consume the refresh slot while the proxy pool is unavailable.
    if ( Cluster::publish_hrw(Cluster::proxy_pool, fmt("%s/%s",drone,controller),
                             pair_confirmed, drone, controller, ts) )
        pair_last_publish[drone,controller]=ts;
    }

event pair_confirmed(drone: addr, controller: addr, ts: time)
    {
    if ( network_time()-ts > correlation_age || ts-network_time() > 5secs ) return;
    if ( Cluster::local_node_type() == Cluster::PROXY )
        Cluster::publish(Cluster::worker_topic, pair_confirmed, drone, controller, ts);
    else if ( Cluster::local_node_type() == Cluster::WORKER )
        receive_pair(drone,controller,ts);
    }

event zeek_init()
    {
    if ( pair_publish_interval <= 0secs || pair_publish_interval >= correlation_age )
        Reporter::fatal("DroneTello::pair_publish_interval must be positive and less than correlation_age");
    }

@endif
