# vrlizate_ble

Bluetooth Low Energy (BLE) GATT duplex controller transport, mutual HMAC-SHA256 challenge-response pairing, QR onboarding UI, and automatic 5 GHz LAN UDP fast-link promotion (`VrHybridBleUdpHostLink` / `VrHybridBleUdpClientLink`) for **VRlizate SDK**.

## Features

- **21-Byte Binary BLE State Wire (`VrBleWireCodec`):** Encodes dual-stick, triggers, pedals, mode, and discrete buttons into a compact 21-byte frame with automatic ATT MTU fragmentation/single-packet promotion (`VrBlePacketLink`).
- **Mutual Session Authentication (`VrBleHostPeer` / `VrBleClientPeer`):** Prevents rogue BLE centrals or spoofed advertisements from injecting input or reading session secrets.
- **Pluggable Native GATT Peripheral (`VrBleGattPeripheralAdapter`):** Defaults to `MethodChannelVrBleGattPeripheral` (`dev.neom.ble/gatt_server` + `dev.neom.ble/gatt_server_events`), enabling zero-duplication integration with `neom_ble` on Android, iOS, and macOS or custom native GATT servers.
- **5 GHz Hybrid BLE/UDP Upgrade (`VrHybridBleUdpHostLink` / `VrHybridBleUdpClientLink`):** Automatically upgrades authenticated BLE sessions to HMAC-authenticated UDP (`dart:io` `RawDatagramSocket`) with discrete button-edge micro-retransmit and seamless BLE failover.
- **Experience Button Contracts (`VrControllerContract`):** Declarative per-experience controller button mapping and HUD hints.

## Platform & Host Integration Contract

`vrlizate_ble` is a Dart package without bundled `android/` or `ios/` native folders of its own. Its capabilities depend on the target runtime and host plugins:

| Layer / Role | Entry Points | Runtime & Plugin Requirements | Behavior in a Standalone SDK Host |
| --- | --- | --- | --- |
| **Wire & Mutual Auth** | `VrBleWireCodec`, `VrBlePacketLink`, `VrBleHostPeer`, `VrBleClientPeer`, `VrControllerContract` | Pure Dart (`crypto` HMAC-SHA256) | Runs in any Dart/Flutter isolate without platform channels. |
| **5 GHz Hybrid UDP Upgrade** | `VrHybridBleUdpHostLink`, `VrHybridBleUdpClientLink` | `dart:io` (`RawDatagramSocket`, `NetworkInterface`) | Supported on Dart VM / native targets (Android, iOS, macOS, Windows, Linux); **not** available on Flutter Web. |
| **Pairing Persistence** | `VrControllerPairingStore`, `VrVisorBleIdentityStore` | `flutter_secure_storage`, `shared_preferences` | Requires host platform implementations of those standard Pub plugins. |
| **Controller / Central Role (Phone Mando)** | `prepareVrBleController`, `VrBleControllerConnector`, `VrBleControllerPage` | Android / iOS + standard Pub plugins `flutter_blue_plus`, `permission_handler`, `mobile_scanner` | Works directly in an Android/iOS host app after `flutter pub get` and OS Bluetooth permissions; throws `StateError` on desktop/unsupported targets. |
| **Visor / Peripheral GATT Role** | `VrBleHost`, `VrDevicePairingPage`, `VrBleGattPeripheralAdapter` | Requires a **host-supplied BLE GATT peripheral backend**: either linking a native plugin serving `dev.neom.ble/gatt_server` + `dev.neom.ble/gatt_server_events` (e.g. `neom_ble`) or registering `VrBleGattPeripheralAdapter.defaultFactory` / passing `VrBleHost(gatt: ...)` | Fails fast with `VrBlePeripheralUnsupportedException` (`isBackendMissing: true` when the channel is unregistered, `false` when hardware/OS reports peripheral mode unsupported) **before** requesting Bluetooth permissions or opening the native `EventChannel`. |
| **Optional Radio Capability Hints** | `VrBlePeerCapabilities` (`vrlizate/device_capabilities`) | Optional Android host `MethodChannel` or `VrBlePeerCapabilities.readPeerSummary` callback | Degrades to `null` on `MissingPluginException` or timeout (900 ms) without blocking BLE or UDP links. |

### Error Distinction in `VrBleHost.start()`

- **`VrBlePeripheralUnsupportedException`:** Thrown when `VrBleGattPeripheralAdapter.isSupported()` returns `false`. Check `error.isBackendMissing` to distinguish an unlinked host peripheral plugin (`MissingPluginException` on `dev.neom.ble/gatt_server`) from a device/OS that lacks BLE peripheral support. `VrDevicePairingPage` surfaces `error.message` directly instead of prompting the user to grant Bluetooth permissions.
- **`StateError` (permissions / radio state):** Thrown only after peripheral support is confirmed when Bluetooth is turned off, required OS permissions (`BLUETOOTH_CONNECT`, `BLUETOOTH_ADVERTISE`) are denied, or native GATT/advertising startup fails.

## License

Apache License 2.0 — see `LICENSE`.

## Pointer posture compatibility

`pointerPostureV1` is an optional, strictly boolean capability negotiated through
challenge/authenticate/ready. Only mutual support enables `pointerPoseReady` in
bit2 of the mode byte; low2 mode bits and all existing flags are preserved. State,
atomic ATT and authenticated UDP lengths remain 21/25/43 bytes. Unnegotiated bits
are rejected; legacy peers keep their original wire format and readiness defaults
to false at a new receiver. `pointerPostureEnabled` exposes the negotiated result.
This transports the sender's inclination qualification; it does not measure pose
or authenticate the physical truth of a sensor reading.
