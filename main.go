// check_strongswan is a Nagios plugin that checks strongSwan connections
// via the vici control interface.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/backslash7/check_strongswan/internal/check"
	"github.com/backslash7/check_strongswan/internal/nagios"
	"github.com/backslash7/check_strongswan/internal/strongswan"
)

const service = "STRONGSWAN"

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("check_strongswan", flag.ContinueOnError)
	var (
		socket      = fs.String("socket", "/var/run/charon.vici", "path to the charon vici socket")
		timeout     = fs.Duration("timeout", 10*time.Second, "overall plugin timeout (must be below the NRPE timeout)")
		showVersion = fs.Bool("version", false, "print version and exit")
		opts        check.Options
	)
	fs.Func("conn", "check only this connection; repeatable or comma-separated (default: all loaded)", func(s string) error {
		opts.Conns = append(opts.Conns, splitList(s)...)
		return nil
	})
	fs.Func("ignore", "exclude this connection; repeatable or comma-separated", func(s string) error {
		opts.Ignore = append(opts.Ignore, splitList(s)...)
		return nil
	})

	lifetime := func(name, usage string, dst **nagios.Range) {
		fs.Func(name, usage, func(s string) error {
			r, err := nagios.ParseLifetime(s)
			if err != nil {
				return err
			}
			*dst = r
			return nil
		})
	}
	const lifetimeHelp = "seconds remaining; bare N means alert below N, Nagios range syntax accepted"
	lifetime("ike-rekey-warn", "WARNING threshold for IKE_SA rekey time ("+lifetimeHelp+")", &opts.IkeRekeyWarn)
	lifetime("ike-rekey-crit", "CRITICAL threshold for IKE_SA rekey time ("+lifetimeHelp+")", &opts.IkeRekeyCrit)
	lifetime("ike-reauth-warn", "WARNING threshold for IKE_SA reauthentication time ("+lifetimeHelp+")", &opts.IkeReauthWarn)
	lifetime("ike-reauth-crit", "CRITICAL threshold for IKE_SA reauthentication time ("+lifetimeHelp+")", &opts.IkeReauthCrit)
	lifetime("child-rekey-warn", "WARNING threshold for CHILD_SA rekey time ("+lifetimeHelp+")", &opts.ChildRekeyWarn)
	lifetime("child-rekey-crit", "CRITICAL threshold for CHILD_SA rekey time ("+lifetimeHelp+")", &opts.ChildRekeyCrit)
	lifetime("child-life-warn", "WARNING threshold for CHILD_SA remaining lifetime ("+lifetimeHelp+")", &opts.ChildLifeWarn)
	lifetime("child-life-crit", "CRITICAL threshold for CHILD_SA remaining lifetime ("+lifetimeHelp+")", &opts.ChildLifeCrit)

	childrenSeverity := fs.String("children-severity", "critical",
		"severity when fewer CHILD_SAs are installed than configured: warning, critical or ok (disable)")

	if err := fs.Parse(args); err != nil {
		return int(nagios.Unknown)
	}
	switch *childrenSeverity {
	case "critical":
		opts.ChildrenSeverity = nagios.Critical
	case "warning":
		opts.ChildrenSeverity = nagios.Warning
	case "ok":
		opts.ChildrenSeverity = nagios.OK
	default:
		return unknown(out, fmt.Errorf("invalid -children-severity %q", *childrenSeverity))
	}
	if *showVersion {
		fmt.Fprintf(out, "check_strongswan %s\n", version)
		return int(nagios.OK)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client, err := strongswan.NewViciClient(*socket)
	if err != nil {
		return unknown(out, err)
	}
	defer client.Close()

	conns, err := client.ListConns(ctx)
	if err != nil {
		return unknown(out, err)
	}
	sas, err := client.ListSAs(ctx)
	if err != nil {
		return unknown(out, err)
	}
	stats, err := client.Stats(ctx)
	if err != nil {
		return unknown(out, err)
	}

	res := check.Evaluate(conns, sas, stats, opts)
	fmt.Fprintln(out, res.Render(service))
	return int(res.Status())
}

func unknown(out io.Writer, err error) int {
	fmt.Fprintf(out, "%s %s - %v\n", service, nagios.Unknown, err)
	return int(nagios.Unknown)
}

func splitList(s string) []string {
	var items []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			items = append(items, part)
		}
	}
	return items
}
