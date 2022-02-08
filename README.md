# egress-auditor

Audit your egress connections and finally populate this OUTPUT chain !

## Summary

egress-auditor will monitor new outbound connections and generate appropriate
iptables rules (or report, or ... depending on [output plugin](#outputs)).

Connections can be detected using several [methods](#inputs).

This is early alpha stuff.

## Quick start

```bash
# add an iptable rules on OUTPUT to send new connections to NFLOG
sudo iptables -I OUTPUT -m state --state NEW -p tcp -j NFLOG --nflog-group 100
go build . 
# start egress-auditor using the nflog input and the same group id used in iptables
sudo ./egress-auditor -i nflog -I nflog:group:100 -o iptables -O iptables:verbose:2
...
# wait a bit
# then Ctrl+C to get iptables rules to allow detected connections
...
```

## Usage

See `-h` for help, and `-l` for the list of input/outpup plugins.

In a nutshell, inputs are added using `-i`, outputs using `-o`.

If plugins need option, they are passed using `-I` for inputs and `-O` for
outputs. For those options, the required format is
`pluginame:optionname:optionvalue`.

For instance, to set verbosity tp 2 for the iptables output plugin, the proper
invocation is:

```
... -O iptables:verbose:2
```

Of course, this implies the iptables output module has been loaded using `-i
iptables` in the same CLI. 

TODO: 
  - -C : how many cnx to capture before bailing out
  - -t: duration to capture before exiting
  - -debug

## Building

```
go build .
```

If you're lazy and do not want to type `sudo` when running `egress-auditor`, you
can give it some capabilities:

```
sudo setcap 'cap_net_admin=+ep' ./egress-auditor 
```

TODO:
  - Makefile
  - goreleaser

## Available modules

### Inputs

- [x] nflog
- [] nfqueue
- [] ebpf

### Outputs

- [x] iptables
- [] json
- [] loki
   
## Licence

MIT

Contributions welcome.
