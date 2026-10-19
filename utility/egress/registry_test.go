package egress

import (
	"sync"
	"testing"
	"time"
)

func snapshot(revision int64, tag string) Snapshot {
	return Snapshot{Revision: revision, LeaseSeconds: 30, Bindings: []Binding{{Inbound: "entry-1", Outbound: tag}}}
}
func TestRegistryRejectsAmbiguityStaleAndMissingWithoutChangingRoutes(t *testing.T) {
	var r Registry
	available := func(s string) bool { return s != "missing" }
	if err := r.Replace(snapshot(2, "old"), available); err != nil {
		t.Fatal(err)
	}
	duplicate := snapshot(3, "new")
	duplicate.Bindings = append(duplicate.Bindings, duplicate.Bindings[0])
	for _, invalid := range []Snapshot{snapshot(1, "old"), snapshot(2, "new"), snapshot(3, "missing"), duplicate, {Revision: 3, LeaseSeconds: 0}} {
		if r.Replace(invalid, available) == nil {
			t.Fatal("invalid snapshot accepted")
		}
		if tag, managed, expired := r.Lookup("entry-1"); tag != "old" || !managed || expired {
			t.Fatal("failed replacement changed route")
		}
	}
	if err := r.Replace(snapshot(2, "old"), available); err != nil {
		t.Fatal("idempotent renewal rejected", err)
	}
}
func TestExpiredBindingCannotBecomeUnmanaged(t *testing.T) {
	var r Registry
	if err := r.Replace(snapshot(1, "old"), func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.expires = time.Now().Add(-time.Second)
	r.mu.Unlock()
	if tag, managed, expired := r.Lookup("entry-1"); tag != "old" || !managed || !expired {
		t.Fatal("expired route can leak")
	}
	if _, managed, _ := r.Lookup("other-entry"); managed {
		t.Fatal("unrelated entry was captured")
	}
}

func TestPublishedRoutingHasNoRefreshDeadlineButExplicitRestrictionsStillApply(t *testing.T) {
	var r Registry
	available := func(string) bool { return true }
	if err := r.ReplacePersistent(snapshot(1, "old"), available); err != nil {
		t.Fatal(err)
	}
	if tag, managed, blocked := r.lookup("entry-1", time.Now().Add(365*24*time.Hour)); tag != "old" || !managed || blocked {
		t.Fatal("published route stopped solely because refresh was unavailable")
	}
	if err := r.ReplacePersistent(snapshot(1, "changed"), available); err == nil {
		t.Fatal("same-revision replacement accepted")
	}
	r.RestrictLease(time.Now().Add(-time.Second))
	if _, managed, blocked := r.Lookup("entry-1"); !managed || !blocked {
		t.Fatal("persistent route bypassed explicit restriction")
	}
	r.RestrictLease(time.Now().Add(time.Hour))
	if _, _, blocked := r.Lookup("entry-1"); !blocked {
		t.Fatal("later restriction revived a blocked route")
	}
	if err := r.ReplacePersistent(snapshot(2, "new"), available); err != nil {
		t.Fatal(err)
	}
	if tag, managed, blocked := r.Lookup("entry-1"); tag != "new" || !managed || blocked {
		t.Fatal("explicit publication could not replace blocked route")
	}
	if err := r.ReplacePersistent(Snapshot{Revision: 3, LeaseSeconds: 30}, available); err != nil {
		t.Fatal(err)
	}
	if r.HasBindings() {
		t.Fatal("explicit withdrawal was ignored")
	}
}
func TestRegistryConcurrentReadersAndAtomicReplacement(t *testing.T) {
	var r Registry
	available := func(string) bool { return true }
	if err := r.Replace(snapshot(1, "old"), available); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				tag, managed, expired, release, revision := r.AcquireObserved("entry-1")
				release()
				if !managed || expired || (tag != "old" && tag != "new") {
					t.Error("partial route observed")
				}
				if (revision%2 == 0 && tag != "new") || (revision%2 != 0 && tag != "old") {
					t.Error("route tag and revision from different snapshots")
				}
			}
		}()
	}
	for i := int64(2); i < 100; i++ {
		tag := "old"
		if i%2 == 0 {
			tag = "new"
		}
		if err := r.Replace(snapshot(i, tag), available); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestEntryIdentityKeepsChangedInboundTagManagedAndRejectsDuplicates(t *testing.T) {
	var r Registry
	s := Snapshot{Revision: 1, LeaseSeconds: 30, Bindings: []Binding{{EntryID: 20000001, Inbound: "Vless_443_20000001", Outbound: "managed"}}}
	if err := r.Replace(s, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"Vless_443_20000001", "Vless_8443_20000001", "Trojan_8443_20000001"} {
		if out, managed, _ := r.Lookup(tag); out != "managed" || !managed {
			t.Fatal("changed tag leaked to default", tag)
		}
	}
	if _, managed, _ := r.Lookup("custom_8443_20000001"); managed {
		t.Fatal("custom unrelated handler captured")
	}
	s.Bindings = append(s.Bindings, Binding{EntryID: 20000001, Inbound: "Vmess_443_20000001", Outbound: "other"})
	if _, _, err := Canonical(s); err == nil {
		t.Fatal("duplicate entry identity accepted")
	}
}
