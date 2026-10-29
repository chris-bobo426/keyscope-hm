import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stepTransform(inputItem: Object): Object {
    let payload = inputItem;
    let outPayload = payload;
    return outPayload;
  }

  private stepCommit(pref: preferences.Preferences, finalItem: Object): void {
    let outPayload = finalItem;
    hilog.info(0x0001, 'CryptoAudit', 'Leaked Key: %{public}s', outPayload);
  }

  public executeTask(pref: preferences.Preferences): void {
    let rand = cryptoFramework.createRandom();
    let publicIv = rand.generateRandomSync(12);
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let secKey = symGen.generateSymKeySync();
    let secBytes = secKey.getEncoded().data;
    let ivNorm = this.normalizeBuffer(publicIv);
    let keyNorm = this.normalizeBuffer(secBytes);
    let payload = keyNorm;
    let mid = this.stepTransform(payload);
    this.stepCommit(pref, mid);
  }

  public normalizeBuffer(srcBuf: Uint8Array): Uint8Array {
    let copied = srcBuf.slice();
    return copied;
  }

}
