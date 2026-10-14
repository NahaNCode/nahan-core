package egress

import "testing"

func TestHandlerRetirementWaitsForEveryBorrower(t *testing.T) {
	var registry Registry
	plan := func(revision int64, tag string) Snapshot {
		return Snapshot{Revision: revision, LeaseSeconds: 30, Bindings: []Binding{{Inbound: "qa", Outbound: tag}}}
	}
	if err := registry.Replace(plan(1, "old"), func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	_, _, _, first := registry.Acquire("qa")
	_, _, _, second := registry.Acquire("qa")
	if err := registry.Replace(plan(2, "new"), func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if registry.CanRetire("old") || registry.CanRetire("new") {
		t.Fatal("borrowed or current handler became retireable")
	}
	first()
	first()
	if registry.CanRetire("old") {
		t.Fatal("double release removed another borrow")
	}
	second()
	if !registry.CanRetire("old") || registry.CanRetire("new") {
		t.Fatal("retirement state incorrect")
	}
}
