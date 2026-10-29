import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stagingSlot: Object = new Object();

  public prepareStage(pref: preferences.Preferences): void {
    let rand = cryptoFramework.createRandom();
    let publicIv = rand.generateRandomSync(12);
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let secKey = symGen.generateSymKeySync();
    let secBytes = secKey.getEncoded().data;
    let ivNorm = this.normalizeBuffer(publicIv);
    let keyNorm = this.normalizeBuffer(secBytes);
    let payload = keyNorm;
    let outPayload = payload;
    this.stagingSlot = outPayload;
  }

  public flushStage(pref: preferences.Preferences): void {
    let outPayload = this.stagingSlot;
    hilog.info(0x0001, 'CryptoAudit', 'Leaked Key: %{public}s', outPayload);
  }

  public normalizeBuffer(srcBuf: Uint8Array): Uint8Array {
    let copied = srcBuf.slice();
    return copied;
  }

}
