module eZeeKonfigurator;

redef Config::config_files += { cat(@DIR, "/conf.dat") };
