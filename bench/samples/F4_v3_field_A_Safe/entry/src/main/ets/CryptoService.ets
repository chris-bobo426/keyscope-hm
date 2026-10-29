import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stagingSlot: Object = new Object();

  public prepareStage(pref: preferences.Preferences): void {
    let huksKek = 'huks_wrap_alias';
    huks.generateKeyItem(huksKek, new Object());
    // @LongTermSecret
    let ltGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let longTermKey = ltGen.generateSymKeySync();
    let ltRaw = longTermKey.getEncoded().data;
    let wrappedLt = huks.wrapKey(ltRaw, huksKek);
    ltRaw.fill(0);
    let agr = cryptoFramework.createKeyAgreement('X25519');
    let ephemeralSecret = agr.generateSecretSync(new Object(), new Object());
    ephemeralSecret.fill(0);
    let payload = wrappedLt;
    let outPayload = payload;
    this.stagingSlot = outPayload;
  }

  public flushStage(pref: preferences.Preferences): void {
    let outPayload = this.stagingSlot;
    pref.putSync('long_term_wrapped', outPayload);
  }

}
