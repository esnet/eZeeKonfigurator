module eZeeKonfigurator;

@load base/utils/active-http
@load base/utils/json

export {
    type Option: record {
        name: string;
        type_name: string;
        value: any;
        doc: string;
    };

    type SensorInfo: record {
    	 hostname:             string &default=gethostname();
	 current_time:         time   &default=current_time();
	 network_time:         time   &default=network_time();
	 pid:                  count  &default=getpid();
	 reading_live_traffic: bool   &default=reading_live_traffic();
	 reading_traces:       bool   &default=reading_traces();
	 zeek_version:         string &default=zeek_version();
    };

    option server_endpoint: string = "";
}

redef Config::config_files += { cat(@DIR, "/conf.dat") };

function notify_server(data: string)
    {
    if (server_endpoint == "" )
        return;

    when (local r = ActiveHTTP::request([$url=server_endpoint, $method="POST", $client_data=data]))
        {
    	print "Rar!";
        }
    timeout 10sec
        {
        print "Oops";
        }
    }

function change_handler(ID: string, new_value: any): any
{
    notify_server(cat("change", ID, new_value));
    return new_value;
}

function dump_ids(): bool
    {
	local ids = global_ids();
	local opts: table[string] of Option;
	for (k in ids)
		{
		local v = ids[k];
		if ( v$option_value )
			opts[k] = Option($name=k, $type_name=v$type_name, $value=v$value, $doc=get_identifier_comments(k));
		}
	print opts;
	return T;
	}

event zeek_init()
	{
	Option::set_change_handler("eZeeKonfigurator::server_endpoint", change_handler);
    	}

event Input::end_of_data(name: string, source: string)
      {
      notify_server(to_json(SensorInfo()));
      dump_ids();
      }

event zeek_done()
      {
      notify_server("done");
      }