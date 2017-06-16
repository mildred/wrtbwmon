#!/usr/bin/awk

function inInterfaces(host){
    return(interfaces ~ "(^| )"host"($| )")
}

function newRule(arp_ip,
    ipt_cmd){
    # checking for existing rules shouldn't be necessary if newRule is
    # always called after db is read, arp table is read, and existing
    # iptables rules are read.
    ipt_cmd="iptables -t mangle -j RETURN -s " arp_ip
    if(debug)
        print ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD" >"/dev/stderr"
    system(ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD")
    ipt_cmd="iptables -t mangle -j RETURN -d " arp_ip
    if(debug)
        print ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD" >"/dev/stderr"
    system(ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD")
}

function total(i){
    return(bw[i "/in"] + bw[i "/out"])
}

function date(format,    cmd, d){
    if(!format) format="%Y-%m-%d_%H:%M:%S"
    cmd="date +" format
    cmd | getline d
    close(cmd)
    #!@todo could start a process with "while true; do date ...; done"
    return(d)
}

BEGIN {
    od=""
    fid=1
    debug=0
    rrd=0
    split(criteria, criteria_list, ",")
    split(validity, validity_list, ",")
    for(i in criteria_list){
        if(!criteria_list[i]) delete criteria_list[i]
        if(!criteria_list[i]) delete validity_list[i]
    }
    for(i in criteria_list){
        c = criteria_list[i]
        v = validity_list[i]
        val[c] = v
        if(debug)
            print "Criteria " c " validity " v >"/dev/stderr"
    }
    run_date=date()
}

/^#/ { # get DB filename
    FS=","
    dbFile=FILENAME
    next
}

# data from database; first file
FNR==NR { #!@todo this doesn't help if the DB file is empty.
    if($1 $2 == "") next
    if($2 == "NA")
	#!@todo could get interface IP here
	n=$1
    else
	n=$2

    hosts[n] = "" # add this host/interface to hosts

    if($9 $10) {
        n = $9 "/" $10 "/" n
        if(!val[$9]) val[$9] = $10
    }

    mac[n]        =  $1
    ip[n]         =  $2
    inter[n]      =  $3
    bw[n "/in"]   =  $4
    bw[n "/out"]  =  $5
    firstDate[n]  =  $7
    lastDate[n]   =  $8
    crit[n]       =  $9
    next
}

# not triggered on the first file
FNR==1 {
    FS=" "
    fid++ #!@todo use fid for all files; may be problematic for empty files
    #if(fid>3) FS=","
    next
}

#fid>3 {
#    if(mac[ip[$1]]) {
#        n=ip[$1]
#    } else if(mac[$1]) {
#        n=$1
#    } else {
#        n=""
#    }
#}

# Add to the database

#fid==4 && n=="" {
#    n = $1
#    mac[n]        =  $1
#    ip[n]         =  $2
#    inter[n]      =  $3
#    bw[n "/in"]   =  $4
#    bw[n "/out"]  =  $5
#    firstDate[n]  =  $7
#    lastDate[n]   =  $8
#    next
#}

#fid==4 {
#    bw[n "/in"]  +=  $4
#    bw[n "/out"] +=  $5
#
#    if(firstDate[n] > $7) firstDate[n] = $7
#    if(lastDate[n] < $8)  lastDate[n] = $8
#    next
#}

# Substract to the database
#fid==5 {
#    bw[n "/in"]  -= $4
#    bw[n "/out"] -= $5
#
#    if(firstDate[n] == $7) firstDate[n] = $8
#    if(lastDate[n] == $8) lastDate[n] = $7
#    next
#}

# arp: ip hw flags hw_addr mask device
fid==2 {
    #!@todo regex match IPs and MACs for sanity
    arp_ip    = $1
    arp_flags = $3
    arp_mac   = $4
    arp_dev   = $6
    if(arp_flags != "0x0" && !(arp_ip in ip)){
	if(debug)
	    print "new host:", arp_ip, arp_flags > "/dev/stderr"
	hosts[arp_ip] = ""
	mac[arp_ip]   = arp_mac
	ip[arp_ip]    = arp_ip
	inter[arp_ip] = arp_dev
	bw[arp_ip "/in"] = bw[arp_ip "/out"] = 0
	firstDate[arp_ip] = lastDate[arp_ip] = run_date
    }
    next
}

#!@todo could use mangle chain totals or tailing "unnact" rules to
# account for data for new hosts from their first presence on the
# network to rule creation. The "unnact" rules would have to be
# maintained at the end of the list, and new rules would be inserted
# at the top.

# skip line
# read the chain name and deal with the data accordingly
fid==3 && $1 == "Chain"{
    rrd=$2 ~ /RRDIPT_.*/
    next
}

fid==3 && rrd && (NF < 9 || $1=="pkts"){ next }

fid==3 && rrd { # iptables input
    if($6 != "*"){
	m=$6
	n=m "/out"
    } else if($7 != "*"){
	m=$7
	n=m "/in"
    } else if($8 != "0.0.0.0/0"){
	m=$8
	n=m "/out"
    } else { # $9 != "0.0.0.0/0"
	m=$9
	n=m "/in"
    }

    # remove host from array; any hosts left in array at END get new
    # iptables rules

    #!@todo this deletes a host if any rule exists; if only one
    # directional rule is removed, this will not remedy the situation
    delete hosts[m]

    if($2 > 0){ # counted some bytes
	if(mode == "diff" || mode == "noUpdate")
	    print n, $2
	if(mode!="noUpdate"){
	    if(inInterfaces(m)){ # if label is an interface
		if(!(m in mac)){ # if label was not in db (also not in
				 # arp table, but interfaces won't be
				 # there anyway)
		    firstDate[m] = run_date
		    mac[m] = inter[m] = m
		    ip[m] = "NA"
		    bw[m "/in"]=bw[m "/out"]= 0
		}
	    }
	    bw[n]+=$2
	    lastDate[m] = run_date

            for(i in criteria_list) {
                c=criteria_list[i]
                v=validity_list[i]
                mm = c "/" v "/" m
                nn = c "/" v "/" n
                bw[nn] += $2
                if(!firstDate[mm]) firstDate[mm] = run_date
                lastDate[mm] = run_date
            }
        }
    }
}

END {
    if(mode=="noUpdate") exit
    close(dbFile)
    system("rm -f " dbFile)
    print "#mac,ip,iface,in,out,total,first_date,last_date,criteria,validity" > dbFile
    OFS=","
    for(i in mac) {
        if(!crit[i]) print mac[i], ip[i], inter[i], bw[i "/in"]+0, bw[i "/out"]+0, total(i)+0, firstDate[i], lastDate[i] > dbFile
    }
    for(c in val) {
        if(c) for(i in mac) {
            n = c "/" val[c] "/" i
            if(lastDate[n]) print mac[i], ip[i], inter[i], bw[n "/in"]+0, bw[n "/out"]+0, total(n)+0, firstDate[n], lastDate[n], c, val[c] > dbFile
        }
    }
    close(dbFile)
    # for hosts without rules
    for(host in hosts) if(!inInterfaces(host) && host != "") newRule(host)
}
