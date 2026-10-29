import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences, modeFlag: boolean): void {
    // 故意使用反向混淆变量名测试是否依赖命名启发式 (打穿 B0)
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
    let branchHolder: Object = payload;
    if (modeFlag) {
      branchHolder = payload;
    }
    payload = branchHolder as any;
    let outPayload = payload;
    pref.putSync('long_term_wrapped', outPayload);
  }

}
