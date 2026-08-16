package nex

import (
	"crypto/rand"
	"sync/atomic"
)

// Notifications protocol (server → client push only).
const (
	ProtocolNotifications          uint16 = 0x0E
	MethodProcessNotificationEvent uint32 = 0x1
)

// Notification event type ids (category*1000 + subtype). These are what the
// console's Pia WaitNotification blocks on after matchmaking.
const (
	NotificationParticipate           uint32 = 3001   // ParticipationEvent.Participate — the pairing unblock
	NotificationEndParticipation      uint32 = 3008   // ParticipationEvent.EndParticipation
	NotificationAddedToGathering      uint32 = 122000 // to a newly-added (non-caller) participant
	NotificationGatheringUnregistered uint32 = 109000 // gathering torn down
	NotificationHostChanged           uint32 = 110000 // host migrated
)

// NotificationEvent is the payload of ProcessNotificationEvent (NEX 4.0). It is
// StructureVersion 0 with all-u64 params and NO MapParam — the MapParam / u32
// variants are rejected outright by the Switch. That's the default and every
// existing title (MK8, Splatoon 2, SSBU, ACNH, ARMS) relies on it unchanged.
type NotificationEvent struct {
	PIDSource uint64
	Type      uint32
	Param1    uint64
	Param2    uint64
	StrParam  string
	Param3    uint64

	// Map, when non-nil, upgrades the encoding to StructureVersion 1 and appends
	// a NEX 4.0+ Map<string, Variant> after Param3 — the "MapParam" the package
	// comment above warns is rejected outright by at least one already-verified
	// title. Opt-in ONLY: leave nil and every title keeps today's byte-for-byte
	// StructureVersion-0 output. Set it only for a title whose retail client is
	// documented/confirmed to require this field on a specific event — e.g. SMB35's
	// Eagle relay handoff (event type 200000, carrying {"url":..., "token":...}),
	// per kinnay/NintendoClients' notification.py NotificationEvent.map (MIT).
	Map map[string]Variant
}

// Levels implements Structure.
func (n *NotificationEvent) Levels() []Level {
	version := uint8(0)
	if n.Map != nil {
		version = 1
	}
	return []Level{{
		Version: version,
		Save: func(o *StreamOut) {
			o.PID(n.PIDSource)
			o.U32(n.Type)
			o.U64(n.Param1)
			o.U64(n.Param2)
			o.String(n.StrParam)
			o.U64(n.Param3)
			if n.Map != nil {
				WriteMap(o, n.Map,
					func(o *StreamOut, k string) { o.String(k) },
					func(o *StreamOut, v Variant) { o.Variant(v) })
			}
		},
		Load: func(i *StreamIn) {
			n.PIDSource = i.PID()
			n.Type = i.U32()
			n.Param1 = i.U64()
			n.Param2 = i.U64()
			n.StrParam = i.String()
			n.Param3 = i.U64()
			// This protocol is server -> client push only (see the package comment
			// below), so nothing here ever decodes a received NotificationEvent in
			// production; the map isn't read back for the same reason the original
			// version-0-only Load never needed to either.
		},
	}}
}

var notifCallCounter uint32

// SendNotification pushes a ProcessNotificationEvent RMC *request* to the target
// connection. The addressing (source stream id) is inherited from the target
// connection's own response path — which is exactly what the Switch requires
// (a hardcoded source port is silently dropped).
func SendNotification(target *Connection, event *NotificationEvent) {
	s := target.Settings
	out := NewStreamOut(s)
	out.Add(event)
	callID := 0xFFFE0000 + atomic.AddUint32(&notifCallCounter, 1)
	target.SendRMC(NewRMCRequest(s, ProtocolNotifications, MethodProcessNotificationEvent, callID, out.Bytes()))
}

// randomBytes returns n cryptographically-random bytes (session keys etc.).
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
