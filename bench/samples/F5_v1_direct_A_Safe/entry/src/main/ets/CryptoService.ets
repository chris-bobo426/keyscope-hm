import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences): void {
    let rand = cryptoFramework.createRandom();
    let publicIv = rand.generateRandomSync(12);
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let secKey = symGen.generateSymKeySync();
    let secBytes = secKey.getEncoded().data;
    let ivNorm = this.normalizeBuffer(publicIv);
    let keyNorm = this.normalizeBuffer(secBytes);
    secBytes.fill(0);
    keyNorm.fill(0);
    let payload = ivNorm;
    let outPayload = payload;
    hilog.info(0x0001, 'CryptoAudit', 'Normalized IV: %{public}s', outPayload);
  }

  public normalizeBuffer(srcBuf: Uint8Array): Uint8Array {
    let copied = srcBuf.slice();
    return copied;
  }

}
