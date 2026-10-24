import { useEffect, useRef, useState } from 'react';
import {
  Alert, FlatList, KeyboardAvoidingView, Modal, Platform, Pressable,
  StyleSheet, Text, TextInput, View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { CameraView, useCameraPermissions } from 'expo-camera';
import AsyncStorage from '@react-native-async-storage/async-storage';

import { base32Decode, parseOtpauthUri, totp } from './src/totp';

const STORAGE_KEY = 'totp-accounts';
const SKEW_OPTIONS = [-30, 0, 30];

function useNow(intervalMs = 250) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

function formatCode(code) {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

function AccountCard({ account, timeMs, onDelete }) {
  const period = account.period || 30;
  const secondsLeft = period - (Math.floor(timeMs / 1000) % period);
  const code = totp(account.secret, { timeMs, period, digits: account.digits || 6 });
  const urgent = secondsLeft <= 5;

  return (
    <Pressable onLongPress={() => onDelete(account)} style={styles.card}>
      <Text style={styles.issuer}>{account.issuer}</Text>
      <Text style={styles.account}>{account.account}</Text>
      <View style={styles.codeRow}>
        <Text style={[styles.code, urgent && styles.urgent]}>{formatCode(code)}</Text>
        <Text style={[styles.seconds, urgent && styles.urgent]}>{secondsLeft}s</Text>
      </View>
      <View style={styles.progressTrack}>
        <View
          style={[styles.progressFill, urgent && styles.progressUrgent,
            { width: `${(secondsLeft / period) * 100}%` }]}
        />
      </View>
    </Pressable>
  );
}

function ScannerModal({ visible, onClose, onScanned }) {
  const [permission, requestPermission] = useCameraPermissions();
  // Ref y no estado: la cámara puede emitir varios eventos antes del re-render
  const locked = useRef(false);

  useEffect(() => { if (visible) locked.current = false; }, [visible]);

  return (
    <Modal visible={visible} animationType="slide" onRequestClose={onClose}>
      <View style={styles.scanner}>
        {!permission ? null : !permission.granted ? (
          <View style={styles.center}>
            <Text style={styles.text}>Se necesita permiso de cámara para escanear el QR.</Text>
            <Pressable style={styles.button} onPress={requestPermission}>
              <Text style={styles.buttonText}>Dar permiso</Text>
            </Pressable>
          </View>
        ) : (
          <CameraView
            style={StyleSheet.absoluteFill}
            facing="back"
            barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
            onBarcodeScanned={({ data }) => {
              if (locked.current) return;
              locked.current = true;
              onScanned(data);
            }}
          />
        )}
        <View style={styles.scanFrame} pointerEvents="none" />
        <Pressable style={[styles.button, styles.closeButton]} onPress={onClose}>
          <Text style={styles.buttonText}>Cancelar</Text>
        </Pressable>
      </View>
    </Modal>
  );
}

function ManualModal({ visible, onClose, onSubmit }) {
  const [name, setName] = useState('');
  const [secret, setSecret] = useState('');

  const submit = () => {
    if (onSubmit(name, secret)) {
      setName('');
      setSecret('');
    }
  };

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={onClose}>
      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : undefined} style={styles.sheetBackdrop}>
        <View style={styles.sheet}>
          <Text style={styles.sheetTitle}>Agregar semilla manualmente</Text>
          <Text style={styles.label}>Nombre de la cuenta</Text>
          <TextInput style={styles.input} value={name} onChangeText={setName}
            placeholder="Taller2MFA:ana" placeholderTextColor="#64748b" />
          <Text style={styles.label}>Semilla Base32 (o URI otpauth://)</Text>
          <TextInput style={[styles.input, styles.mono]} value={secret} onChangeText={setSecret}
            placeholder="JBSWY3DPEHPK3PXP" placeholderTextColor="#64748b"
            autoCapitalize="characters" autoCorrect={false} multiline />
          <View style={styles.row}>
            <Pressable style={[styles.button, styles.secondary]} onPress={onClose}>
              <Text style={[styles.buttonText, styles.secondaryText]}>Cancelar</Text>
            </Pressable>
            <Pressable style={styles.button} onPress={submit}>
              <Text style={styles.buttonText}>Guardar</Text>
            </Pressable>
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

export default function App() {
  const now = useNow();
  const [accounts, setAccounts] = useState([]);
  const [skew, setSkew] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [manual, setManual] = useState(false);

  useEffect(() => {
    AsyncStorage.getItem(STORAGE_KEY)
      .then((raw) => raw && setAccounts(JSON.parse(raw)))
      .catch(() => {});
  }, []);

  const persist = (next) => {
    setAccounts(next);
    AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(next)).catch(() => {});
  };

  const addAccount = (parsed) => {
    // Re-escanear el mismo secreto reemplaza la cuenta en vez de duplicarla
    const others = accounts.filter((a) => a.secret !== parsed.secret);
    persist([...others, { id: `${Date.now()}`, ...parsed }]);
  };

  const handleScanned = (data) => {
    try {
      addAccount(parseOtpauthUri(data));
      setScanning(false);
    } catch (e) {
      Alert.alert('QR inválido', e.message, [{ text: 'OK', onPress: () => setScanning(false) }]);
    }
  };

  const handleManual = (name, input) => {
    try {
      if (input.trim().toLowerCase().startsWith('otpauth://')) {
        addAccount(parseOtpauthUri(input));
      } else {
        const secret = input.replace(/\s/g, '').toUpperCase();
        if (base32Decode(secret).length < 10) throw new Error('La semilla es demasiado corta');
        const [issuer, account] = name.includes(':') ? name.split(/:(.*)/) : ['Manual', name];
        addAccount({ secret, issuer: issuer.trim() || 'Manual', account: (account || 'cuenta').trim(), period: 30, digits: 6 });
      }
      setManual(false);
      return true;
    } catch (e) {
      Alert.alert('Semilla inválida', e.message);
      return false;
    }
  };

  const confirmDelete = (account) => {
    Alert.alert('Eliminar cuenta', `¿Eliminar ${account.issuer} (${account.account})?`, [
      { text: 'Cancelar', style: 'cancel' },
      { text: 'Eliminar', style: 'destructive', onPress: () => persist(accounts.filter((a) => a.id !== account.id)) },
    ]);
  };

  const timeMs = now + skew * 1000;

  return (
    <View style={styles.container}>
      <StatusBar style="light" />
      <Text style={styles.title}>Authenticator</Text>
      <Text style={styles.subtitle}>
        RFC 6238 · HMAC-SHA1 · funciona en modo avión · {new Date(timeMs).toLocaleTimeString()}
      </Text>

      <View style={styles.skewRow}>
        <Text style={styles.label}>Simular desfase de reloj:</Text>
        {SKEW_OPTIONS.map((s) => (
          <Pressable key={s} onPress={() => setSkew(s)} style={[styles.chip, skew === s && styles.chipActive]}>
            <Text style={[styles.chipText, skew === s && styles.chipTextActive]}>
              {s === 0 ? '0s' : `${s > 0 ? '+' : ''}${s}s`}
            </Text>
          </Pressable>
        ))}
      </View>

      <FlatList
        data={accounts}
        keyExtractor={(a) => a.id}
        renderItem={({ item }) => <AccountCard account={item} timeMs={timeMs} onDelete={confirmDelete} />}
        ListEmptyComponent={
          <Text style={[styles.text, styles.empty]}>
            Sin cuentas. Escanea el QR del backend o pega la semilla Base32.
          </Text>
        }
        contentContainerStyle={{ paddingBottom: 24 }}
      />
      {accounts.length > 0 && <Text style={styles.hint}>Mantén presionada una cuenta para eliminarla</Text>}

      <View style={styles.row}>
        <Pressable style={styles.button} onPress={() => setScanning(true)}>
          <Text style={styles.buttonText}>Escanear QR</Text>
        </Pressable>
        <Pressable style={[styles.button, styles.secondary]} onPress={() => setManual(true)}>
          <Text style={[styles.buttonText, styles.secondaryText]}>Pegar semilla</Text>
        </Pressable>
      </View>

      <ScannerModal visible={scanning} onClose={() => setScanning(false)} onScanned={handleScanned} />
      <ManualModal visible={manual} onClose={() => setManual(false)} onSubmit={handleManual} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0f172a', paddingTop: 60, paddingHorizontal: 16, paddingBottom: 32 },
  title: { color: '#f8fafc', fontSize: 28, fontWeight: '700' },
  subtitle: { color: '#94a3b8', fontSize: 12, marginTop: 4, marginBottom: 12 },
  text: { color: '#e2e8f0', fontSize: 15, textAlign: 'center' },
  empty: { marginTop: 48, color: '#94a3b8' },
  hint: { color: '#64748b', fontSize: 12, textAlign: 'center', marginBottom: 8 },
  label: { color: '#94a3b8', fontSize: 13, marginVertical: 6 },
  card: { backgroundColor: '#1e293b', borderRadius: 14, padding: 16, marginBottom: 12 },
  issuer: { color: '#38bdf8', fontSize: 14, fontWeight: '600' },
  account: { color: '#cbd5e1', fontSize: 13 },
  codeRow: { flexDirection: 'row', alignItems: 'baseline', justifyContent: 'space-between', marginTop: 6 },
  code: { color: '#f8fafc', fontSize: 46, fontWeight: '700', letterSpacing: 2, fontVariant: ['tabular-nums'] },
  seconds: { color: '#94a3b8', fontSize: 16, fontVariant: ['tabular-nums'] },
  urgent: { color: '#f87171' },
  progressTrack: { height: 6, backgroundColor: '#334155', borderRadius: 3, overflow: 'hidden', marginTop: 8 },
  progressFill: { height: 6, backgroundColor: '#38bdf8' },
  progressUrgent: { backgroundColor: '#f87171' },
  skewRow: { flexDirection: 'row', alignItems: 'center', gap: 6, marginBottom: 12, flexWrap: 'wrap' },
  chip: { paddingHorizontal: 10, paddingVertical: 4, borderRadius: 999, borderWidth: 1, borderColor: '#334155' },
  chipActive: { backgroundColor: '#38bdf8', borderColor: '#38bdf8' },
  chipText: { color: '#cbd5e1', fontSize: 13 },
  chipTextActive: { color: '#0f172a', fontWeight: '700' },
  row: { flexDirection: 'row', gap: 10 },
  button: { flex: 1, backgroundColor: '#38bdf8', paddingVertical: 14, borderRadius: 10, alignItems: 'center', marginTop: 8 },
  buttonText: { color: '#0f172a', fontWeight: '700', fontSize: 16 },
  secondary: { backgroundColor: '#1e293b', borderWidth: 1, borderColor: '#334155' },
  secondaryText: { color: '#e2e8f0' },
  scanner: { flex: 1, backgroundColor: '#000', justifyContent: 'flex-end' },
  center: { flex: 1, justifyContent: 'center', padding: 24 },
  scanFrame: {
    position: 'absolute', top: '30%', alignSelf: 'center', width: 240, height: 240,
    borderWidth: 3, borderColor: '#38bdf8', borderRadius: 16,
  },
  closeButton: { flex: 0, margin: 24 },
  sheetBackdrop: { flex: 1, justifyContent: 'flex-end', backgroundColor: 'rgba(0,0,0,0.6)' },
  sheet: { backgroundColor: '#1e293b', padding: 20, borderTopLeftRadius: 18, borderTopRightRadius: 18, paddingBottom: 36 },
  sheetTitle: { color: '#f8fafc', fontSize: 18, fontWeight: '700', marginBottom: 8 },
  input: { backgroundColor: '#0f172a', color: '#f8fafc', borderRadius: 8, padding: 12, fontSize: 15, borderWidth: 1, borderColor: '#334155' },
  mono: { fontFamily: Platform.select({ ios: 'Menlo', default: 'monospace' }) },
});
