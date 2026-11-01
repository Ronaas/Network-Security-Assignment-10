@load base/frameworks/notice

module UDPScanDetect;

export {
    redef enum Notice::Type += {
        UDP_Port_Scan
    };
}

const threshold = 20 &redef;

global attempts: table[addr, addr] of count &default=0;
global notice_count: table[addr, addr] of count &default=0;

event new_connection(c: connection)
    {
    if ( c$id$proto == 17 )
        {
        local src = c$id$orig_h;
        local dst = c$id$resp_h;

        ++attempts[src, dst];

        if ( attempts[src, dst] >= threshold )
            {
            notice_count[src, dst] += 1;

            NOTICE([
                $note=UDP_Port_Scan,
                $msg=fmt("Possible UDP scan from %s to %s. Attempts: %d. Previous notices: %d",
                    src, dst, attempts[src, dst],
                    notice_count[src, dst] - 1)
            ]);

            attempts[src, dst] = 0;
            }
        }
    }
