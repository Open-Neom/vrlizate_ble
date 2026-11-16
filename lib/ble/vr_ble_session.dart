import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:vrlizate_joystick/vrlizate_joystick.dart';

import 'vr_ble_wire.dart';

/// A fresh random service UUID identifies a viewer session, never its secret.
String newVrBleServiceUuid() {
  final bytes = _randomBytes(16);
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

bool isVrBleServiceUuid(String? value) =>
    value != null &&
    RegExp(
      r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
    ).hasMatch(value);

List<int> _randomBytes(int count) {
  final random = Random.secure();
  return List.generate(count, (_) => random.nextInt(256));
}

String _nonce() => base64UrlEncode(_randomBytes(32));
bool _validNonce(Object? value) {
  if (value is! String || value.length != 44) return false;
  try {
    return base64Url.decode(value).length == 32;
  } catch (_) {
    return false;
  }
}

String _proof(String token, String role, String server, String client) => Hmac(
  sha256,
  utf8.encode(token),
).convert(utf8.encode('vrlizate-ble-v1/$role/$server/$client')).toString();

bool _matches(Object? actual, String expected) {
  if (actual is! String || actual.length != expected.length) return false;
  var diff = 0;
  for (var i = 0; i < expected.length; i++) {
    diff |= actual.codeUnitAt(i) ^ expected.codeUnitAt(i);
  }
  return diff == 0;
}

/// Buffered complete packets, with one bounded ATT writer per physical peer.
/// Authentication consumes packets before they can reach the controller sink.
class VrBlePacketLink implements VrControllerLink {
  VrBlePacketLink({
    required Future<void> Function(Uint8List) writeChunk,
    Future<void> Function(Uint8List chunk, {required bool reliable})?
    writeChunkWithReliability,
    required this.onClose,
  }) {
    _writer = VrBlePacketWriter(
      writeChunk: writeChunk,
      writeChunkWithReliability: writeChunkWithReliability,
      onError: (error) => _fail(
        VrControllerConnectionException(
          'Bluetooth: no se pudo enviar el paquete.',
          canRetry: error is! FormatException && error is! ArgumentError,
        ),
      ),
    );
    _messages = StreamController<Object?>(
      sync: true,
      onListen: () {
        _listening = true;
        _scheduleDelivery();
      },
      onPause: () => _paused = true,
      onResume: () {
        _paused = false;
        _scheduleDelivery();
      },
      onCancel: () {
        _listening = false;
        unawaited(close());
      },
    );
  }

  final Future<void> Function() onClose;
  late final StreamController<Object?> _messages;
  final _pending = ListQueue<String>();
  bool _listening = false;
  bool _paused = false;
  bool _deliveryScheduled = false;
  final _reader = VrBleReassembler();
  late final VrBlePacketWriter _writer;
  void Function(String)? onPacket;
  void Function()? onClosed;
  bool _open = true;
  bool _authenticated = false;
  bool _edgeTurnIntentEnabled = false;
  bool _pointerPostureEnabled = false;
  bool _shoulderButtonsEnabled = false;
  VrControllerConnectionException? _failure;

  /// A local failure, recorded before teardown. A remote close alone provides
  /// no evidence that a pairing secret has expired or been rejected.
  VrControllerConnectionException? get failure => _failure;

  /// True only after the optional 21-byte state flag was mutually negotiated.
  bool get edgeTurnIntentEnabled => _edgeTurnIntentEnabled;

  /// False for legacy peers: pointer readiness cannot be inferred from axes.
  bool get pointerPostureEnabled => _pointerPostureEnabled;
  bool get shoulderButtonsEnabled => _shoulderButtonsEnabled;

  /// True once negotiated ATT MTU >= 28 enables single-PDU 25-byte states.
  bool get singlePacketStateEnabled =>
      _reader.allowSinglePacketState && _writer.allowSinglePacketState;

  void enableSinglePacketState() {
    _reader.allowSinglePacketState = true;
    _writer.allowSinglePacketState = true;
  }

  void _enableEdgeTurnIntent() {
    _edgeTurnIntentEnabled = true;
    _writer.allowEdgeTurnIntent = true;
  }

  void _enableShoulderButtons() {
    _shoulderButtonsEnabled = true;
    _writer.allowShoulderButtons = true;
  }

  void _enablePointerPosture() {
    _pointerPostureEnabled = true;
    _writer.allowPointerPosture = true;
  }

  @override
  bool get isOpen => _open;
  @override
  Stream<Object?> get messages => _messages.stream;

  void receive(Uint8List chunk) {
    if (!_open) return;
    try {
      final packet = _reader.add(chunk);
      if (packet == null) return;
      final json = VrBleWireCodec.decode(
        packet,
        allowEdgeTurnIntent: _edgeTurnIntentEnabled,
        allowPointerPosture: _pointerPostureEnabled,
        allowShoulderButtons: _shoulderButtonsEnabled,
      );
      if (onPacket case final handler?) {
        handler(json);
      } else {
        // A physical link cannot implicitly authorize input before a peer has
        // installed its challenge/proof handler.
        _rejectProtocol();
      }
    } on VrBleFragmentInterrupted {
      // A dropped/expired ATT fragment says nothing about the pairing secret.
      // Never deliver partial input: close and authenticate a fresh link, but
      // allow the controller to recover instead of treating it as a bad QR.
      _fail(
        const VrControllerConnectionException(
          'Bluetooth: se interrumpió un paquete. Reconectando el mando.',
        ),
      );
    } catch (_) {
      _rejectProtocol();
    }
  }

  static bool _isCoalesceableStateJson(String json) {
    // Control messages always carry a "type" field and must never be dropped.
    return !json.contains('"type"');
  }

  bool _evictOldestCoalesceableState() {
    if (_pending.length < 2) return false;
    final items = _pending.toList(growable: true);
    // Prefer dropping an older state frame followed immediately by another
    // state frame so control ordering and the latest snapshot stay intact.
    for (var i = 0; i < items.length - 1; i++) {
      if (_isCoalesceableStateJson(items[i]) &&
          _isCoalesceableStateJson(items[i + 1])) {
        items.removeAt(i);
        _pending
          ..clear()
          ..addAll(items);
        return true;
      }
    }
    for (var i = 0; i < items.length - 1; i++) {
      if (_isCoalesceableStateJson(items[i])) {
        items.removeAt(i);
        _pending
          ..clear()
          ..addAll(items);
        return true;
      }
    }
    return false;
  }

  void deliver(String json) {
    if (!_open) return;
    if (_pending.length >= 8) {
      if (!_authenticated) {
        _rejectProtocol();
        return;
      }
      if (!_evictOldestCoalesceableState()) {
        // Non-coalesceable control backlog on a paused/unattached listener is
        // bounded at 8 packets, but remains retryable after authentication.
        _fail(
          const VrControllerConnectionException(
            'Bluetooth: cola de paquetes saturada temporalmente; reconectando el mando.',
            canRetry: true,
          ),
        );
        return;
      }
    }
    _pending.add(json);
    _scheduleDelivery();
  }

  void _scheduleDelivery() {
    if (_deliveryScheduled || !_listening || _paused || !_open) return;
    _deliveryScheduled = true;
    // Never emit synchronously from StreamController.onListen. Keep a bounded
    // queue until the caller receives ready and attaches its single listener.
    scheduleMicrotask(() {
      _deliveryScheduled = false;
      while (_open && _listening && !_paused && _pending.isNotEmpty) {
        _messages.add(_pending.removeFirst());
      }
    });
  }

  @override
  void add(Object data) {
    if (!_open) return;
    if (data is! String) {
      _rejectProtocol();
      return;
    }
    try {
      _writer.add(data);
    } catch (_) {
      _rejectProtocol();
    }
  }

  void _rejectProtocol() => _fail(
    const VrControllerConnectionException(
      'Bluetooth: el enlace no superó la validación del protocolo.',
      canRetry: false,
    ),
  );

  void _fail(VrControllerConnectionException error) {
    if (!_open) return;
    _failure = error;
    unawaited(close());
  }

  @override
  Future<void> close([int? code, String? reason]) async {
    if (!_open) return;
    _open = false;
    _writer.close();
    _reader.reset();
    _pending.clear();
    try {
      onClosed?.call();
    } catch (_) {
      /* Cleanup still owns native close. */
    }
    // An authenticated consumer must see a permanent protocol rejection before
    // done, so it does not reconnect to the same invalid session in a loop.
    // Defer stream events to avoid reentrant addError from a sync listener.
    // close() must not wait forever if no service ever listened (bad proof).
    final failure = _failure;
    if (_authenticated && failure != null) {
      scheduleMicrotask(() {
        _messages.addError(failure);
        unawaited(_messages.close());
      });
    } else {
      unawaited(_messages.close());
    }
    try {
      await onClose();
    } catch (_) {
      /* Already gone at native layer. */
    }
  }
}

/// Mutual QR-secret challenge/proof. No token is advertised or sent by BLE.
/// This authenticates pairing, not subsequent packet encryption or ranging.
class VrBleHostPeer {
  VrBleHostPeer({
    required this.link,
    required this.sessionToken,
    required this.onAuthenticated,
    this.supportsEdgeTurnIntent = true,
    this.supportsPointerPosture = true,
    this.supportsShoulderButtons = true,
    Duration timeout = const Duration(seconds: 10),
  }) {
    _validatePeerOptions(sessionToken, timeout);
    if (!link.isOpen) {
      throw const VrControllerConnectionException(
        'BLE link is already closed.',
      );
    }
    link.onPacket = _receive;
    link.onClosed = () => _deadline.cancel();
    _deadline = Timer(timeout, () => link.close());
    link.add(
      jsonEncode({
        'type': 'challenge',
        'nonce': _serverNonce,
        if (supportsEdgeTurnIntent) 'edgeTurnIntent': true,
        if (supportsPointerPosture) 'pointerPostureV1': true,
        if (supportsShoulderButtons) _shoulderButtonsCapability: true,
      }),
    );
  }
  final VrBlePacketLink link;
  final String sessionToken;
  final bool supportsEdgeTurnIntent;
  final bool supportsPointerPosture;
  final bool supportsShoulderButtons;
  final bool Function(VrControllerLink) onAuthenticated;
  final _serverNonce = _nonce();
  late final Timer _deadline;
  bool authenticated = false;

  void _receive(String packet) {
    final object = jsonDecode(packet);
    if (authenticated) {
      if (_isHandshake(object)) {
        link._rejectProtocol();
        return;
      }
      link.deliver(packet);
      return;
    }
    if (object is! Map ||
        object['type'] != 'authenticate' ||
        !_validCapabilities(object) ||
        !_validNonce(object['nonce']) ||
        !_matches(
          object['proof'],
          _proof(
            sessionToken,
            'child',
            _serverNonce,
            object['nonce'] as String,
          ),
        )) {
      link._rejectProtocol();
      return;
    }
    _deadline.cancel();
    final edgeTurnIntent =
        supportsEdgeTurnIntent && object['edgeTurnIntent'] == true;
    if (edgeTurnIntent) link._enableEdgeTurnIntent();
    final pointerPosture =
        supportsPointerPosture && object['pointerPostureV1'] == true;
    if (pointerPosture) link._enablePointerPosture();
    final shoulderButtons =
        supportsShoulderButtons && object[_shoulderButtonsCapability] == true;
    if (shoulderButtons) link._enableShoulderButtons();
    // Queue the server proof before attach emits its initial mode command.
    link.add(
      jsonEncode({
        'type': 'ready',
        if (edgeTurnIntent) 'edgeTurnIntent': true,
        if (pointerPosture) 'pointerPostureV1': true,
        if (shoulderButtons) _shoulderButtonsCapability: true,
        'proof': _proof(
          sessionToken,
          'parent',
          _serverNonce,
          object['nonce'] as String,
        ),
      }),
    );
    if (!link.isOpen || !onAuthenticated(link)) {
      unawaited(link.close());
      return;
    }
    authenticated = true;
    link._authenticated = true;
  }
}

class VrBleClientPeer {
  VrBleClientPeer({
    required this.link,
    required this.sessionToken,
    this.supportsEdgeTurnIntent = true,
    this.supportsPointerPosture = true,
    this.supportsShoulderButtons = true,
    Duration timeout = const Duration(seconds: 10),
  }) {
    _validatePeerOptions(sessionToken, timeout);
    if (!link.isOpen) {
      throw const VrControllerConnectionException(
        'BLE link is already closed.',
      );
    }
    link.onPacket = _receive;
    link.onClosed = () {
      _deadline.cancel();
      if (!_ready.isCompleted) {
        _ready.completeError(
          link.failure ??
              const VrControllerConnectionException(
                'Bluetooth: el visor cerró la conexión antes de autenticar.',
              ),
        );
      }
    };
    _deadline = Timer(timeout, () {
      link._fail(
        const VrControllerConnectionException(
          'Bluetooth: se agotó el tiempo de autenticación.',
        ),
      );
    });
  }
  final VrBlePacketLink link;
  final String sessionToken;
  final bool supportsEdgeTurnIntent;
  final bool supportsPointerPosture;
  final bool supportsShoulderButtons;
  final _ready = Completer<VrControllerLink>();
  final _clientNonce = _nonce();
  late final Timer _deadline;
  String? _serverNonce;
  bool _edgeTurnIntentRequested = false;
  bool _pointerPostureRequested = false;
  bool _shoulderButtonsRequested = false;
  bool _authenticated = false;
  Future<VrControllerLink> get ready => _ready.future;

  void _receive(String packet) {
    final object = jsonDecode(packet);
    if (_authenticated) {
      if (_isHandshake(object)) {
        link._rejectProtocol();
        return;
      }
      link.deliver(packet);
      return;
    }
    if (object is! Map || !_validCapabilities(object)) {
      link._rejectProtocol();
      return;
    }
    if (_serverNonce == null &&
        object['type'] == 'challenge' &&
        _validNonce(object['nonce'])) {
      _serverNonce = object['nonce'] as String;
      _edgeTurnIntentRequested =
          supportsEdgeTurnIntent && object['edgeTurnIntent'] == true;
      _pointerPostureRequested =
          supportsPointerPosture && object['pointerPostureV1'] == true;
      _shoulderButtonsRequested =
          supportsShoulderButtons && object[_shoulderButtonsCapability] == true;
      link.add(
        jsonEncode({
          'type': 'authenticate',
          if (_edgeTurnIntentRequested) 'edgeTurnIntent': true,
          if (_pointerPostureRequested) 'pointerPostureV1': true,
          if (_shoulderButtonsRequested) _shoulderButtonsCapability: true,
          'nonce': _clientNonce,
          'proof': _proof(sessionToken, 'child', _serverNonce!, _clientNonce),
        }),
      );
    } else if (_serverNonce != null &&
        object['type'] == 'ready' &&
        _matches(
          object['proof'],
          _proof(sessionToken, 'parent', _serverNonce!, _clientNonce),
        )) {
      if (object['edgeTurnIntent'] == true && !_edgeTurnIntentRequested) {
        link._rejectProtocol();
        return;
      }
      if (object['pointerPostureV1'] == true && !_pointerPostureRequested) {
        link._rejectProtocol();
        return;
      }
      if (object[_shoulderButtonsCapability] == true &&
          !_shoulderButtonsRequested) {
        link._rejectProtocol();
        return;
      }
      if (object[_shoulderButtonsCapability] == true) {
        link._enableShoulderButtons();
      }
      if (object['edgeTurnIntent'] == true) {
        link._enableEdgeTurnIntent();
      }
      if (object['pointerPostureV1'] == true) {
        link._enablePointerPosture();
      }
      _authenticated = true;
      link._authenticated = true;
      _deadline.cancel();
      _ready.complete(link);
    } else {
      // Preserve the local proof/protocol rejection before onClosed supplies
      // its generic transport error. It does not prove that the QR expired.
      link._rejectProtocol();
    }
  }
}

bool _isHandshake(Object? value) =>
    value is Map &&
    const {'challenge', 'authenticate', 'ready'}.contains(value['type']);

const _shoulderButtonsCapability = 'shoulderButtonsV1';

bool _validCapabilities(Map value) =>
    (!value.containsKey('edgeTurnIntent') || value['edgeTurnIntent'] is bool) &&
    (!value.containsKey('pointerPostureV1') ||
        value['pointerPostureV1'] is bool) &&
    (!value.containsKey(_shoulderButtonsCapability) ||
        value[_shoulderButtonsCapability] is bool);

void _validatePeerOptions(String token, Duration timeout) {
  if (token.isEmpty) {
    throw ArgumentError.value(token, 'sessionToken', 'Must not be empty.');
  }
  if (timeout <= Duration.zero) {
    throw ArgumentError.value(timeout, 'timeout', 'Must be positive.');
  }
}
