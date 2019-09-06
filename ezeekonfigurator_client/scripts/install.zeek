module eZeeKonfigurator;

@load base/utils/active-http
@load base/utils/queue
@load base/utils/json


export {
    ## The eZeeKonfigurator URL. Automatically set during zkg install.
    option server_endpoint: string = "";

    ## Upon startup, we tell the server what options are available to be set.    
    type OptionInfo: record {
    	 ## Zeek data type (count, interval, etc.)
	 type_name: string;
	 ## Current value
         value: any;
	 ## The Zeekygen docstring
         doc: string;
    };

    ## A table, indexed by the name of the option, with the info for that option.
    type OptionList: table[string] of OptionInfo;

    ## This calls global_ids and builds our OptionList for IDs that are options.
    global dump_ids: function(): OptionList;

    ## This is the list of options.
    type OptionListMessage: record {
    	 options: OptionList &default=dump_ids();
    };

    ## Some basic info about ourselves.
    type SensorInfoMessage: record {
    	 ## Sensor hostname
    	 hostname:             string &default=gethostname();
	 ## Current time
	 current_time:         time   &default=current_time();
	 ## Network time (time of last packet)
	 network_time:         time   &default=network_time();
	 ## Process ID
	 pid:                  count  &default=getpid();
	 ## Are we sniffing an interface?
	 reading_live_traffic: bool   &default=reading_live_traffic();
	 ## Are we reading a PCAP?
	 reading_traces:       bool   &default=reading_traces();
	 ## Zeek version
	 zeek_version:         string &default=zeek_version();
    };

    ## What we actually send the server.
    type ServerMessage: record {
    	 ## When we constructed this message
	 ts:	    time &default=current_time();
	 ## The actual payload
	 data:	    any;
    };

    ## We're responsbile for exit-ing the process.
    const trigger_terminate = F &redef;
}

redef Config::config_files += { cat(@DIR, "/conf.dat") };

## If we receive data before we know where to send it, queue it here.
global queued_data = Queue::init();

## Internal function to actually send the data to the server
function _send_data(msg: ServerMessage, queued: bool &default=F)
    {
    local url = server_endpoint;
    if (msg$data is SensorInfoMessage)
        {
        url = cat(url, "sensor_info/");
	}
    else if (msg$data is OptionListMessage)
        {
    	url = cat(url, "option_list/");
	}

    when (local r = ActiveHTTP::request([$url=url, $method="POST", $client_data=to_json(msg)]))
        {
	if ( queued )
	    	Queue::get(queued_data);
        }
    timeout 10sec
        {
        return;
        }
    }


event clear_queue()
    {
    # Try sending our queued data
    if ( Queue::len(queued_data) > 0 )
       {
       local vec: vector of ServerMessage = vector();
       Queue::get_vector(queued_data, vec);
       for (k in vec)
             {
	     _send_data(vec[k], T);
       	     }
       }

    if ( Queue::len(queued_data) > 0 )
       schedule 2sec { clear_queue() };
    else if ( trigger_terminate )
       terminate();
    }

function notify_server(data: any)
    {
    local msg = ServerMessage($data=data);

    # We don't have an endpoint yet, so queue the data until we (hopefully) do.
    if (server_endpoint == "" )
       {
       Queue::put(queued_data, msg);
       return;
       }

    _send_data(msg);
    }

function dump_ids(): OptionList
    {
	local ids = global_ids();
	local opts = OptionList();
	for (k in ids)
		{
		local v = ids[k];
		if ( v$option_value )
		        {
			opts[k] = OptionInfo($type_name=type_name(v$value), $value=v$value, $doc=get_identifier_comments(k));
			}
		}
	return opts;
	}

event zeek_init()
	{
	notify_server(SensorInfoMessage());
	notify_server(OptionListMessage());
    	}

redef exit_only_after_terminate = T;
redef eZeeKonfigurator::trigger_terminate = T;

event Input::end_of_data(name: string, source: string)
	{
	if ( /^config-/ in name )
	   event clear_queue();
 	}