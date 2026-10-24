import { useEffect, useMemo, useState } from 'react';
import { Button, SafeAreaView, StyleSheet, Text, TextInput, View } from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as SecureStore from 'expo-secure-store';
import { StatusBar } from 'expo-status-bar';
import { base32Decode, PERIOD, totp } from './totp';

const STORE_KEY = 'totp_account';

// otpauth://totp/Issuer:user?secret=XXXX&issuer=Issuer
function parseOtpauth(uri) {
  const secret = /[?&]secret=([^&]+)/i.exec(uri)?.[1];
  if (!uri.startsWith('otpauth://totp/') || !secret) throw new Error('QR no es un otpauth://totp válido');
  const label = decodeURIComponent(uri.slice('otpauth://totp/'.length).split('?')[0]);
  return { secret: decodeURIComponent(secret), label };
}

function checkSecret(secret) {
  if (base32Decode(secret).length < 10) throw new Error('Semilla demasiado corta');
}

export default function App() {
  const [account, setAccount] = useState(null);
  const [now, setNow] = useState(Date.now() / 1000);
  const [manual, setManual] = useState('');
  const [error, setError] = useState('');
  const [scanning, setScanning] = useState(false);
  const [permission, requestPermission] = useCameraPermissions();

  useEffect(() => {
    SecureStore.getItemAsync(STORE_KEY).then((v) => v && setAccount(JSON.parse(v)));
    const id = setInterval(() => setNow(Date.now() / 1000), 250);
    return () => clearInterval(id);
  }, []);

  const key = useMemo(() => (account ? base32Decode(account.secret) : null), [account]);
  const counter = Math.floor(now / PERIOD);
  const code = useMemo(() => (key ? totp(key, now) : null), [key, counter]);
  const remaining = PERIOD - (now % PERIOD);

  async function save(acc) {
    try {
      checkSecret(acc.secret);
      await SecureStore.setItemAsync(STORE_KEY, JSON.stringify(acc));
      setAccount(acc);
      setError('');
      setManual('');
    } catch (e) {
      setError(e.message);
    }
  }

  async function startScan() {
    if (!permission?.granted && !(await requestPermission()).granted) return setError('Sin permiso de cámara');
    setScanning(true);
  }

  function onScan({ data }) {
    setScanning(false);
    try { save(parseOtpauth(data)); } catch (e) { setError(e.message); }
  }

  async function reset() {
    await SecureStore.deleteItemAsync(STORE_KEY);
    setAccount(null);
  }

  if (scanning) {
    return (
      <View style={styles.flex}>
        <CameraView style={styles.flex} barcodeScannerSettings={{ barcodeTypes: ['qr'] }} onBarcodeScanned={onScan} />
        <Button title="Cancelar" onPress={() => setScanning(false)} />
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      <Text style={styles.title}>Mi Authenticator</Text>
      {account ? (
        <>
          <Text style={styles.label}>{account.label}</Text>
          <Text style={styles.code} selectable>{code.slice(0, 3)} {code.slice(3)}</Text>
          <View style={styles.barBg}>
            <View style={[styles.bar, { width: `${(remaining / PERIOD) * 100}%`, backgroundColor: remaining < 6 ? '#ff6b6b' : '#4dabf7' }]} />
          </View>
          <Text style={styles.label}>{Math.ceil(remaining)} s · contador C = {counter}</Text>
          <View style={styles.gap} />
          <Button title="Quitar cuenta" color="#868e96" onPress={reset} />
        </>
      ) : (
        <>
          <Button title="Escanear QR" onPress={startScan} />
          <Text style={styles.label}>o pega la semilla Base32:</Text>
          <TextInput
            style={styles.input}
            value={manual}
            onChangeText={setManual}
            autoCapitalize="characters"
            autoCorrect={false}
            placeholder="JBSWY3DPEHPK3PXP..."
            placeholderTextColor="#666"
          />
          <Button title="Guardar semilla" onPress={() => save({ secret: manual.trim(), label: 'Cuenta manual' })} />
        </>
      )}
      {!!error && <Text style={styles.error}>{error}</Text>}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1 },
  container: { flex: 1, backgroundColor: '#15171c', alignItems: 'stretch', justifyContent: 'center', padding: 24 },
  title: { color: '#fff', fontSize: 24, fontWeight: '700', textAlign: 'center', marginBottom: 24 },
  label: { color: '#adb5bd', textAlign: 'center', marginVertical: 8 },
  code: { color: '#fff', fontSize: 64, fontWeight: '700', textAlign: 'center', fontVariant: ['tabular-nums'], letterSpacing: 4 },
  barBg: { height: 8, backgroundColor: '#343a40', borderRadius: 4, overflow: 'hidden', marginTop: 12 },
  bar: { height: 8 },
  input: { color: '#fff', borderColor: '#495057', borderWidth: 1, borderRadius: 8, padding: 12, marginVertical: 8 },
  error: { color: '#ff6b6b', textAlign: 'center', marginTop: 16 },
  gap: { height: 32 },
});
