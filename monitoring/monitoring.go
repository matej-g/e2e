// Copyright (c) The EfficientGo Authors.
// Licensed under the Apache License 2.0.

package e2emonitoring

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/cgroups"
	"github.com/efficientgo/e2e"
	e2edb "github.com/efficientgo/e2e/db"
	e2einteractive "github.com/efficientgo/e2e/interactive"
	"github.com/efficientgo/e2e/monitoring/promconfig"
	sdconfig "github.com/efficientgo/e2e/monitoring/promconfig/discovery/config"
	"github.com/efficientgo/e2e/monitoring/promconfig/discovery/targetgroup"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/prometheus/common/model"
	"gopkg.in/yaml.v2"
)

type Service struct {
	p *e2edb.Prometheus
}

type listener struct {
	p *e2edb.Prometheus
}

func (l *listener) updateConfig(started map[string]e2e.Instrumented) error {
	// TODO(bwplotka): Scrape our process metrics too?

	cfg := promconfig.Config{
		GlobalConfig: promconfig.GlobalConfig{
			ExternalLabels: map[model.LabelName]model.LabelValue{"prometheus": model.LabelValue(l.p.Name())},
			ScrapeInterval: model.Duration(15 * time.Second),
		},
	}

	add := func(name string, instr e2e.Instrumented) {
		scfg := &promconfig.ScrapeConfig{
			JobName:                name,
			ServiceDiscoveryConfig: sdconfig.ServiceDiscoveryConfig{StaticConfigs: []*targetgroup.Group{{}}},
		}
		for _, t := range instr.MetricTargets() {
			scfg.ServiceDiscoveryConfig.StaticConfigs[0].Targets = append(scfg.ServiceDiscoveryConfig.StaticConfigs[0].Targets, map[model.LabelName]model.LabelValue{
				model.AddressLabel: model.LabelValue(t.InternalEndpoint),
			})

			if t.MetricPath != "/metrics" {
				// TODO(bwplotka) Add relabelling rule to change `__path__`.
				panic("Different metrics endpoints are not implemented yet")
			}
		}
		cfg.ScrapeConfigs = append(cfg.ScrapeConfigs, scfg)
	}

	add("e2emonitoring-prometheus", l.p)
	for name, s := range started {
		add(name, s)
	}

	o, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return l.p.SetConfig(string(o))
}

func (l *listener) OnRunnableChange(started []e2e.Runnable) error {
	s := map[string]e2e.Instrumented{}
	for _, r := range started {
		instr, ok := r.(e2e.Instrumented)
		if !ok {
			continue
		}
		s[r.Name()] = instr
	}

	return l.updateConfig(s)
}

type opt struct {
	pidAsContainer int
}

// WithPIDAsContainer sets option that makes monitoring to organize cgroups in a way that makes cadvisor
// to watch those as it would be any other container.
// Use it with os.Getpid() to get current process monitored like that.
// NOTE: This option requires a manual on-off per machine/restart setup that will be printed on first start (permissions).
func WithPIDAsContainer(pid int) func(*opt) {
	return func(o *opt) {
		o.pidAsContainer = pid
	}
}

type Option func(*opt)

// Start deploys monitoring service which deploys Prometheus that monitors all registered InstrumentedServices
// in environment.
func Start(env e2e.Environment, opts ...Option) (_ *Service, err error) {
	opt := opt{}
	for _, o := range opts {
		o(&opt)
	}

	p := e2edb.NewPrometheus(env, "monitoring")
	l := &listener{p: p}
	if err := l.updateConfig(map[string]e2e.Instrumented{}); err != nil {
		return nil, err
	}
	env.AddListener(l)

	var path []string
	if opt.pidAsContainer != 0 {
		// Do cgroup magic allowing us to monitor given PID as container.
		path, err = setupPIDAsContainer(env, opt.pidAsContainer)
		if err != nil {
			return nil, err
		}
	}

	if err := newCadvisor(env, "cadvisor", path...).Start(); err != nil {
		return nil, err
	}
	return &Service{p: p}, e2e.StartAndWaitReady(p)
}

func (s *Service) OpenUserInterfaceInBrowser() error {
	return e2einteractive.OpenInBrowser("http://" + s.p.Endpoint(e2edb.AccessPortName))
}

func newCadvisor(env e2e.Environment, name string, cgroupPrefixes ...string) *e2e.InstrumentedRunnable {
	return e2e.NewInstrumentedRunnable(env, name, map[string]int{"http": 8080}, "http").Init(e2e.StartOptions{
		// See https://github.com/google/cadvisor/blob/master/docs/runtime_options.md.
		Command: e2e.NewCommand(
			// TODO(bwplotka): Add option to scope to dockers only from this network.
			"--docker_only=true",
			"--raw_cgroup_prefix_whitelist="+strings.Join(cgroupPrefixes, ","),
		),
		Image: "gcr.io/cadvisor/cadvisor:v0.37.5",
		// See https://github.com/google/cadvisor/blob/master/docs/running.md.
		Volumes: []string{
			"/:/rootfs:ro",
			"/var/run:/var/run:rw",
			"/sys:/sys:ro",
			"/var/lib/docker/:/var/lib/docker:ro",
		},
		UserNs:     "host",
		Privileged: true,
	})
}

const (
	mountpoint     = "/sys/fs/cgroup"
	cgroupSubGroup = "e2e"
)

func setupPIDAsContainer(env e2e.Environment, pid int) ([]string, error) {
	// Try to setup test cgroup to check if we have perms.
	{
		c, err := cgroups.New(cgroups.V1, cgroups.StaticPath(filepath.Join(cgroupSubGroup, "__test__")), &specs.LinuxResources{})
		if err != nil {
			if os.IsPermission(err) {
				uid := os.Getuid()

				var cmds []string

				ss, cerr := cgroups.V1()
				if cerr != nil {
					return nil, cerr
				}

				for _, s := range ss {
					cmds = append(cmds, fmt.Sprintf("sudo mkdir -p %s && sudo chown -R %d %s",
						filepath.Join(mountpoint, string(s.Name()), cgroupSubGroup),
						uid,
						filepath.Join(mountpoint, string(s.Name()), cgroupSubGroup),
					))
				}
				return nil, errors.Errorf("e2e does not have permissions, run following command: %q; err: %v", strings.Join(cmds, " && "), err)
			}
			return nil, err
		}
		if err := c.Delete(); err != nil {
			return nil, err
		}
	}

	// Delete previous cgroup if it exists.
	root, err := cgroups.Load(cgroups.V1, cgroups.RootPath)
	if err != nil {
		return nil, err
	}

	l, err := cgroups.Load(cgroups.V1, cgroups.StaticPath(filepath.Join(cgroupSubGroup, env.Name())))
	if err != nil {
		if err != cgroups.ErrCgroupDeleted {
			return nil, err
		}
	} else {
		if err := l.MoveTo(root); err != nil {
			return nil, err
		}
		if err := l.Delete(); err != nil {
			return nil, err
		}
	}

	// Create cgroup that will contain our process.
	c, err := cgroups.New(cgroups.V1, cgroups.StaticPath(filepath.Join(cgroupSubGroup, env.Name())), &specs.LinuxResources{})
	if err != nil {
		return nil, err
	}
	if err := c.Add(cgroups.Process{Pid: pid}); err != nil {
		return nil, err
	}
	env.AddCloser(func() {
		if err := l.MoveTo(root); err != nil {
			fmt.Println("Failed to move all processes", err)
		}
		if err := c.Delete(); err != nil {
			// TODO(bwplotka): This never works, but not very important, fix it.
			fmt.Println("Failed to delete cgroup", err)
		}
	})

	return []string{filepath.Join("/", cgroupSubGroup, env.Name())}, nil
}
