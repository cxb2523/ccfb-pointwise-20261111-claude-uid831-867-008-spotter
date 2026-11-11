package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/parser"
)

// loadPodSecurityRules loads the two pod security-context rules from the
// repository rules/ directory so tests exercise the exact shipped CEL.
func loadPodSecurityRules(t *testing.T) (privEsc, hostNS *models.SpotterRule) {
	t.Helper()

	load := func(path string) *models.SpotterRule {
		result, err := parser.LoadFromFile(filepath.Join("..", "..", "rules", path))
		if err != nil {
			t.Fatalf("failed to load rule %s: %v", path, err)
		}
		if len(result.Errors) > 0 {
			t.Fatalf("rule %s has parse errors: %v", path, result.Errors)
		}
		if len(result.Rules) != 1 {
			t.Fatalf("expected exactly 1 rule in %s, got %d", path, len(result.Rules))
		}
		return result.Rules[0]
	}

	return load("spotter-workload-001-allow-privilege-escalation.yaml"),
		load("spotter-platform-001-host-namespaces.yaml")
}

// evaluate is a small helper that runs one rule against one resource and
// fails the test on engine-level errors or CEL evaluation errors.
func evaluate(t *testing.T, e *CELEngine, rule *models.SpotterRule, resource map[string]interface{}) *models.ValidationResult {
	t.Helper()

	result, err := e.EvaluateRule(context.Background(), rule, resource)
	if err != nil {
		t.Fatalf("EvaluateRule(%s) returned error: %v", rule.GetID(), err)
	}
	if result == nil {
		t.Fatalf("EvaluateRule(%s) returned nil result, resource should match rule criteria", rule.GetID())
	}
	if result.Message != "" && result.Passed == false &&
		len(result.Message) >= 21 && result.Message[:21] == "CEL evaluation error:" {
		t.Fatalf("CEL evaluation error for %s: %s", rule.GetID(), result.Message)
	}
	return result
}

// podWithContainers builds a bare Pod resource with the given container lists.
func podWithContainers(containers, initContainers, ephemeralContainers []interface{}) map[string]interface{} {
	spec := map[string]interface{}{}
	if containers != nil {
		spec["containers"] = containers
	}
	if initContainers != nil {
		spec["initContainers"] = initContainers
	}
	if ephemeralContainers != nil {
		spec["ephemeralContainers"] = ephemeralContainers
	}
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "test-pod", "namespace": "default"},
		"spec":       spec,
	}
}

// workloadWithPodSpec wraps a pod spec at the depth expected for the kind:
// Deployment -> spec.template.spec, CronJob -> spec.jobTemplate.spec.template.spec.
func workloadWithPodSpec(kind, apiVersion string, podSpec map[string]interface{}) map[string]interface{} {
	resource := map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]interface{}{"name": "test-" + kind, "namespace": "default"},
	}
	switch kind {
	case "Deployment":
		resource["spec"] = map[string]interface{}{
			"template": map[string]interface{}{"spec": podSpec},
		}
	case "CronJob":
		resource["spec"] = map[string]interface{}{
			"jobTemplate": map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{"spec": podSpec},
				},
			},
		}
	default:
		panic("unsupported kind")
	}
	return resource
}

func container(name string, securityContext map[string]interface{}) map[string]interface{} {
	c := map[string]interface{}{"name": name, "image": "nginx:1.25"}
	if securityContext != nil {
		c["securityContext"] = securityContext
	}
	return c
}

func TestPodSecurityRuleMetadata(t *testing.T) {
	privEsc, hostNS := loadPodSecurityRules(t)

	if privEsc.GetID() != "spotter-workload-001" {
		t.Errorf("unexpected privesc rule ID: %s", privEsc.GetID())
	}
	if privEsc.GetSeverity() != "medium" {
		t.Errorf("privesc severity = %q, want medium", privEsc.GetSeverity())
	}
	if privEsc.GetCategory() != "workload" {
		t.Errorf("privesc category = %q, want workload", privEsc.GetCategory())
	}

	if hostNS.GetID() != "spotter-platform-001" {
		t.Errorf("unexpected host namespaces rule ID: %s", hostNS.GetID())
	}
	if hostNS.GetSeverity() != "high" {
		t.Errorf("host namespaces severity = %q, want high", hostNS.GetSeverity())
	}
	if hostNS.GetCategory() != "platform" {
		t.Errorf("host namespaces category = %q, want platform", hostNS.GetCategory())
	}
}

func TestAllowPrivilegeEscalationRule(t *testing.T) {
	privEsc, _ := loadPodSecurityRules(t)
	eng, err := NewCELEngine()
	if err != nil {
		t.Fatalf("failed to create CEL engine: %v", err)
	}

	sc := func(ape bool) map[string]interface{} {
		return map[string]interface{}{"allowPrivilegeEscalation": ape}
	}

	tests := []struct {
		name     string
		resource map[string]interface{}
		wantPass bool
	}{
		// 命中:显式 true
		{
			name:     "hit: pod container explicit true",
			resource: podWithContainers([]interface{}{container("app", sc(true))}, nil, nil),
			wantPass: false,
		},
		{
			name:     "hit: initContainer explicit true",
			resource: podWithContainers(nil, []interface{}{container("init", sc(true))}, nil),
			wantPass: false,
		},
		{
			name:     "hit: ephemeralContainer explicit true",
			resource: podWithContainers(nil, nil, []interface{}{container("debug", sc(true))}),
			wantPass: false,
		},
		// 显式 false:绝对不能误报
		{
			name: "pass: all container types explicit false",
			resource: podWithContainers(
				[]interface{}{container("app", sc(false))},
				[]interface{}{container("init", sc(false))},
				[]interface{}{container("debug", sc(false))},
			),
			wantPass: true,
		},
		// 缺省:K8s 默认 true,必须命中
		{
			name:     "hit: container without securityContext (default true)",
			resource: podWithContainers([]interface{}{container("app", nil)}, nil, nil),
			wantPass: false,
		},
		{
			name: "hit: securityContext present but field unset (default true)",
			resource: podWithContainers([]interface{}{
				container("app", map[string]interface{}{"runAsNonRoot": true}),
			}, nil, nil),
			wantPass: false,
		},
		{
			name:     "hit: initContainer without securityContext (default true)",
			resource: podWithContainers(nil, []interface{}{container("init", nil)}, nil),
			wantPass: false,
		},
		// 深层嵌套:Deployment / CronJob pod template 路径
		{
			name: "hit: deployment template container unset",
			resource: workloadWithPodSpec("Deployment", "apps/v1", map[string]interface{}{
				"containers": []interface{}{container("app", nil)},
			}),
			wantPass: false,
		},
		{
			name: "pass: deployment template container explicit false",
			resource: workloadWithPodSpec("Deployment", "apps/v1", map[string]interface{}{
				"containers": []interface{}{container("app", sc(false))},
			}),
			wantPass: true,
		},
		{
			name: "hit: cronjob jobTemplate container explicit true",
			resource: workloadWithPodSpec("CronJob", "batch/v1", map[string]interface{}{
				"containers": []interface{}{container("job", sc(true))},
			}),
			wantPass: false,
		},
		{
			name: "hit: cronjob jobTemplate initContainer unset",
			resource: workloadWithPodSpec("CronJob", "batch/v1", map[string]interface{}{
				"containers":     []interface{}{container("job", sc(false))},
				"initContainers": []interface{}{container("init", nil)},
			}),
			wantPass: false,
		},
		{
			name: "pass: cronjob jobTemplate all explicit false",
			resource: workloadWithPodSpec("CronJob", "batch/v1", map[string]interface{}{
				"containers":     []interface{}{container("job", sc(false))},
				"initContainers": []interface{}{container("init", sc(false))},
			}),
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluate(t, eng, privEsc, tt.resource)
			if result.Passed != tt.wantPass {
				t.Errorf("Passed = %v, want %v (message: %s)", result.Passed, tt.wantPass, result.Message)
			}
		})
	}
}

// TestAllowPrivilegeEscalationAggregation verifies the engine aggregates
// multiple violating containers into a single result per rule+resource
// instead of emitting one finding per container.
func TestAllowPrivilegeEscalationAggregation(t *testing.T) {
	privEsc, _ := loadPodSecurityRules(t)
	eng, err := NewCELEngine()
	if err != nil {
		t.Fatalf("failed to create CEL engine: %v", err)
	}

	pod := podWithContainers(
		[]interface{}{
			container("app1", nil),
			container("app2", map[string]interface{}{"allowPrivilegeEscalation": true}),
		},
		[]interface{}{container("init", nil)},
		nil,
	)

	results, err := eng.EvaluateRules(context.Background(), []*models.SpotterRule{privEsc}, pod)
	if err != nil {
		t.Fatalf("EvaluateRules returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 aggregated result for multi-container violation, got %d", len(results))
	}
	if results[0].Passed {
		t.Error("expected aggregated result to be a violation")
	}
}

func TestHostNamespacesRule(t *testing.T) {
	_, hostNS := loadPodSecurityRules(t)
	eng, err := NewCELEngine()
	if err != nil {
		t.Fatalf("failed to create CEL engine: %v", err)
	}

	podWithSpec := func(extra map[string]interface{}) map[string]interface{} {
		spec := map[string]interface{}{
			"containers": []interface{}{container("app", nil)},
		}
		for k, v := range extra {
			spec[k] = v
		}
		return map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]interface{}{"name": "test-pod", "namespace": "default"},
			"spec":       spec,
		}
	}

	tests := []struct {
		name     string
		resource map[string]interface{}
		wantPass bool
	}{
		// 命中
		{
			name:     "hit: pod hostNetwork true",
			resource: podWithSpec(map[string]interface{}{"hostNetwork": true}),
			wantPass: false,
		},
		{
			name:     "hit: pod hostPID true",
			resource: podWithSpec(map[string]interface{}{"hostPID": true}),
			wantPass: false,
		},
		// 显式 false:不误报
		{
			name:     "pass: pod hostNetwork and hostPID explicit false",
			resource: podWithSpec(map[string]interface{}{"hostNetwork": false, "hostPID": false}),
			wantPass: true,
		},
		// 缺省:host 命名空间默认 false,不应命中
		{
			name:     "pass: pod without host namespace fields",
			resource: podWithSpec(nil),
			wantPass: true,
		},
		// 深层嵌套
		{
			name: "hit: deployment template hostPID true",
			resource: workloadWithPodSpec("Deployment", "apps/v1", map[string]interface{}{
				"hostPID":    true,
				"containers": []interface{}{container("app", nil)},
			}),
			wantPass: false,
		},
		{
			name: "hit: cronjob jobTemplate hostNetwork true",
			resource: workloadWithPodSpec("CronJob", "batch/v1", map[string]interface{}{
				"hostNetwork": true,
				"containers":  []interface{}{container("job", nil)},
			}),
			wantPass: false,
		},
		{
			name: "pass: cronjob jobTemplate clean",
			resource: workloadWithPodSpec("CronJob", "batch/v1", map[string]interface{}{
				"containers": []interface{}{container("job", nil)},
			}),
			wantPass: true,
		},
		{
			name: "pass: deployment template clean",
			resource: workloadWithPodSpec("Deployment", "apps/v1", map[string]interface{}{
				"containers": []interface{}{container("app", nil)},
			}),
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluate(t, eng, hostNS, tt.resource)
			if result.Passed != tt.wantPass {
				t.Errorf("Passed = %v, want %v (message: %s)", result.Passed, tt.wantPass, result.Message)
			}
		})
	}
}

// TestHostNamespacesShortPathSafety ensures a bare Pod (short path) does not
// cause a CEL evaluation error when the rule also guards deeper paths —
// has() layering must prevent dereferencing missing spec.template etc.
func TestHostNamespacesShortPathSafety(t *testing.T) {
	_, hostNS := loadPodSecurityRules(t)
	eng, err := NewCELEngine()
	if err != nil {
		t.Fatalf("failed to create CEL engine: %v", err)
	}

	// Minimal pod: no template/jobTemplate keys at all.
	pod := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "bare-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{container("app", nil)},
		},
	}

	result := evaluate(t, eng, hostNS, pod)
	if !result.Passed {
		t.Errorf("bare pod should pass host namespaces rule, got violation: %s", result.Message)
	}
}
