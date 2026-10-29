import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stagingSlot: Object = new Object();

  public prepareStage(pref: preferences.Preferences): void {
    let symGen = cryptoFramework.createSymKeyGenerator('AES256');
    let sessionKey = symGen.generateSymKeySync();
    let rawBytes = sessionKey.getEncoded().data;
    let md = cryptoFramework.createMd('SHA256');
    let fingerprintBlob = md.digestSync(rawBytes);
    rawBytes.fill(0);
    let payload = fingerprintBlob;
    let outPayload = payload;
    this.stagingSlot = outPayload;
  }

  public flushStage(pref: preferences.Preferences): void {
    let outPayload = this.stagingSlot;
    pref.putSync('key_sha256_fingerprint', outPayload);
  }

}
