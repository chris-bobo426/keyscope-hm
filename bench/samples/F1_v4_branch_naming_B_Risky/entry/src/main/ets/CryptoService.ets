import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences, modeFlag: boolean): void {
    // 故意使用反向混淆变量名测试是否依赖命名启发式 (打穿 B0)
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let publicConfigAlias = symGen.generateSymKeySync();
    let encodedBlob = publicConfigAlias.getEncoded();
    let payload = encodedBlob.data;
    let branchHolder: Object = payload;
    if (modeFlag) {
      branchHolder = payload;
    }
    payload = branchHolder as any;
    let b64Helper = new util.Base64Helper();
    let outPayload = b64Helper.encodeToStringSync(payload);
    pref.putSync('saved_key_ref', outPayload);
  }

}
