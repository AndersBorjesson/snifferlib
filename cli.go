package snifferlib

import (
	"fmt"
	"log"
)

const version = "v0.6.2"

// func NewApp() *cobra.Command {
// 	defaultOpts := DefaultOptions()

// 	opt := Options{}
// 	var mode int
// 	var unit string
// 	var list bool

// 	app := &cobra.Command{
// 		Use:     "sniffer",
// 		Short:   "# A modern alternative network traffic sniffer.",
// 		Version: version,
// 		Run: func(cmd *cobra.Command, args []string) {
// 			if list {
// 				devices, err := ListAllDevices()
// 				if err != nil {
// 					exit(err.Error())
// 				}
// 				for _, device := range devices {
// 					fmt.Println(device.Name)
// 				}
// 				return
// 			}
// 			opt.ViewMode = ViewMode(mode)
// 			opt.Unit = Unit(unit)
// 			if err := opt.Validate(); err != nil {
// 				exit(err.Error())
// 			}

// 			sniffer, err := NewSniffer(opt)
// 			if err != nil {
// 				exit(err.Error())
// 			}
// 			defer sniffer.Close()
// 			sniffer.Start()
// 		},
// 		Example: `  # bytes mode in MB unit
//   $ sniffer -u MB

//   # only capture the TCP protocol packets with lo,eth prefixed devices
//   $ sniffer -b tcp -d lo -d eth`,
// 	}

// 	app.Flags().BoolVarP(&list, "list", "l", false, "list all devices name")
// 	app.Flags().BoolVarP(&opt.AllDevices, "all-devices", "a", false, "listen all devices if present")
// 	app.Flags().StringVarP(&opt.BPFFilter, "bpf", "b", defaultOpts.BPFFilter, "specify string pcap filter with the BPF syntax")
// 	app.Flags().IntVarP(&opt.Interval, "interval", "i", defaultOpts.Interval, "interval for refresh rate in seconds")
// 	app.Flags().StringArrayVarP(&opt.DevicesPrefix, "devices-prefix", "d", defaultOpts.DevicesPrefix, "prefixed devices to monitor")
// 	app.Flags().BoolVarP(&opt.DisableDNSResolve, "no-dns-resolve", "n", defaultOpts.DisableDNSResolve, "disable the DNS resolution")
// 	app.Flags().IntVarP(&mode, "mode", "m", int(defaultOpts.ViewMode), "view mode of sniffer (0: bytes 1: packets 2: plot)")
// 	app.Flags().StringVarP(&unit, "unit", "u", defaultOpts.Unit.String(), "unit of traffic stats, optional: B, Kb, KB, Mb, MB, Gb, GB")

// 	app.Flags().PrintDefaults()
// 	return app
// }

func UseAllDevices() []string {
	devices, err := ListAllDevices()
	if err != nil {
		log.Fatalln("ListAllDevices failed:", err)
	}
	devNames := make([]string, 0, len(devices))
	for _, dev := range devices {
		if dev.Name != "any" {
			devNames = append(devNames, dev.Name)
		}
	}
	fmt.Println(devNames)
	return devNames
}

type SnifferLib struct {
	sniffer *Sniffer
}

func (s *SnifferLib) Close() {
	s.sniffer.Close()
}

func (s *SnifferLib) GetStats() *Snapshot {
	s.sniffer.Refresh()

	return (s.sniffer.statsManager.GetStats()).(*Snapshot)
}

func NewSnifferLib() *SnifferLib {
	defaultOpts := DefaultOptions()
	defaultOpts.DevicesPrefix = UseAllDevices()

	sniffer, err := NewSniffer(defaultOpts)
	if err != nil {
		exit(err.Error())
	}
	return &SnifferLib{sniffer}
}

// func main() {

// 	// devices, err := ListAllDevices()
// 	// fmt.Println(devices, err)
// 	defaultOpts := DefaultOptions()
// 	defaultOpts.DevicesPrefix = UseAllDevices()

// 	fmt.Println(defaultOpts)
// 	sniffer, err := NewSniffer(defaultOpts)
// 	if err != nil {
// 		exit(err.Error())
// 	}
// 	defer sniffer.Close()
// 	for {
// 		sniffer.Refresh()
// 		A := (sniffer.statsManager.GetStats())
// 		B := A.(*Snapshot)
// 		for l1, l2 := range (*B).Connections {
// 			fmt.Println(l1, l2)
// 		}
// 		// fmt.Println((*B).Processes)
// 		// fmt.Println("sniffer.statsManager.stat")
// 		// fmt.Println(sniffer.statsManager.stat)
// 		time.Sleep(1 * time.Second)
// 	}
// 	// app := NewApp()
// 	// if err := app.Execute(); err != nil {
// 	// 	exit(err.Error())
// 	// }
// }
