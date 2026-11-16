## 1.0.0

- Initial public VRlizate SDK v1.0 release of `vrlizate_ble`.
- Extracted VR-focused BLE GATT duplex transport (`VrBleHost`, `VrBleControllerConnector`), 21-byte wire codec (`VrBleWireCodec`), mutual HMAC session authentication (`VrBleHostPeer`, `VrBleClientPeer`), QR pairing page (`VrControllerPairingPage`), secure pairing store (`VrControllerPairingStore`), experience controller contracts (`VrControllerContract`), and 5 GHz hybrid BLE/UDP fast-link (`VrHybridBleUdpHostLink`, `VrHybridBleUdpClientLink`).
- Added `VrBleGattPeripheralAdapter` and `MethodChannelVrBleGattPeripheral` for pluggable native GATT server hosting compatible out-of-the-box with `neom_ble`.
