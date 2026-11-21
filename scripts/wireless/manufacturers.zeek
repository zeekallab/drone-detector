# Remote ID serial number -> manufacturer (and model, with the optional FAA file).
#
# ANSI/CTA-2063-A serial numbers: 4-character manufacturer code, 1 length
# character (1-9, A-F = 1-15), then the manufacturer's serial. Example:
# 1581F6Z9C238D00323P4 = code 1581 (DJI), length F (15), serial 6Z9C238D00323P4.
#
# Two sources, the file wins when it matches:
#   1. manufacturer_codes: a built-in table of well-known codes (redef to extend).
#   2. model_file (optional): FAA-accepted Remote ID serials and serial ranges with
#      make and model, read with the Input framework and re-read when it changes.
#      Build it with tools/faa_to_zeek.py.
module DroneManufacturer;

export {
    ## Manufacturer code (first 4 serial characters) -> manufacturer.
    const manufacturer_codes: table[string] of string = {
        ["1581"] = "DJI",
        ["1748"] = "Autel Robotics",
        ["1668"] = "Skydio",
        ["1596"] = "Dronetag",          # add-on broadcast module
        ["1588"] = "Parrot",
        ["1587"] = "AgEagle (senseFly)",
        ["1744"] = "Wingtra",
        ["1701"] = "Percepto",
        ["1633"] = "Wing Aviation",
    } &redef;

    ## Optional FAA serial file (Zeek TSV: serial_start serial_end make model).
    ## Empty disables it. Relative paths resolve against Zeek's working directory.
    const model_file = "" &redef;

    type Identity: record {
        ## Empty when the serial matches neither source.
        manufacturer: string &default="";
        model: string &optional;
        ## "faa-list" or "manufacturer-code".
        source: string &optional;
    };
    global identify: function(serial: string): Identity;
}

type Key: record {
    serial_start: string;
    serial_end: string;
};
type Val: record {
    make: string;
    model: string &optional;
};
type Range: record {
    start: string;
    end: string;
    make: string;
    model: string &optional;
};

# Filled by the Input framework (no per-row events), then indexed once per read.
global serials: table[string, string] of Val = table();
global exact: table[string] of Range = table();
global ranges: table[string] of vector of Range = table();

event Input::end_of_data(name: string, source: string)
    {
    if ( name != "drone-manufacturers" ) return;
    local e: table[string] of Range = table();
    local r: table[string] of vector of Range = table();
    for ( [start,end] in serials )
        {
        local v=serials[start,end];
        if ( |start| < 5 || |start| != |end| ) next;
        local x=Range($start=to_upper(start),$end=to_upper(end),$make=v$make);
        if ( v?$model ) x$model=v$model;
        if ( x$start == x$end ) { e[x$start]=x; next; }
        local code=x$start[0:4];
        if ( code !in r ) r[code]=vector();
        r[code]+=x;
        }
    exact=e; ranges=r;
    Reporter::info(fmt("drone-detector: loaded %d Remote ID serials and %d range groups from %s",
        |exact|,|ranges|,source));
    }

function lookup_file(s: string): Range
    {
    local none=Range($start="",$end="",$make="");
    if ( s in exact ) return exact[s];
    local code=s[0:4];
    if ( code !in ranges ) return none;
    for ( i in ranges[code] )
        {
        local x=ranges[code][i];
        if ( |x$start| == |s| && x$start <= s && s <= x$end ) return x;
        }
    return none;
    }

function identify(serial: string): Identity
    {
    local s=to_upper(serial);
    if ( |s| < 5 ) return Identity();
    local hit=lookup_file(s);
    if ( hit$make != "" )
        {
        local id=Identity($manufacturer=hit$make,$source="faa-list");
        if ( hit?$model ) id$model=hit$model;
        return id;
        }
    if ( s[0:4] in manufacturer_codes )
        return Identity($manufacturer=manufacturer_codes[s[0:4]],$source="manufacturer-code");
    return Identity();
    }

event zeek_init()
    {
    if ( model_file == "" ) return;
    Input::add_table([$source=model_file,$name="drone-manufacturers",$idx=Key,$val=Val,
        $destination=serials,$mode=Input::REREAD]);
    }
