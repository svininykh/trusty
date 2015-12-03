
import java.security.Provider;
import java.security.Security;
import java.security.KeyStore;
import java.security.Signature;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

/**
 *
 * @author adil <berikuly_a@pki.gov.kz>
 */
public class LoadProvider {
    
    public static void main(String[] args) {
        
        // Инициализация провайдера
        Provider kalkanProvider = new KalkanProvider();
        
        
        //Добавление провайдера в java.security.Security
        boolean exists = false;
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            if (p.getName().equals(kalkanProvider.getName())) {
                exists = true;
            }
        }
        if (!exists) {
            Security.addProvider(kalkanProvider);
        }
        
        // Для дальнейшего использования наименования провайдера определяется
        //1
         String providerName = kalkanProvider.getName();
        //2 или
        providerName = KalkanProvider.PROVIDER_NAME;

	// при использовании экземпляров JCE необходимо указывать криптопровайдер KalkanCrypt
	// например,
	KeyStore.getInstance("PKCS12", providerName);
	Signature.getInstance("SHA256withRSA", kalkanProvider);
    }
}
