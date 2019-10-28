package com.chinadci.rdc.ssoserver.config;

import com.chinadci.rdc.ssoserver.utils.DefaultPasswordEncoderFactories;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;


@Import(AuthorizationServerEndpointsConfiguration.class)
@Configuration
//@EnableAuthorizationServer
public class Oauth2AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {


    @Autowired
    private PasswordEncoder passwordEncoder;




    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();;
    }



    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception
    {

        clients.inMemory()
                .withClient("SampleClientId")
                .secret(passwordEncoder.encode("secret"))
                .authorizedGrantTypes("authorization_code","password", "client_credentials","implicit","refresh_token")
                .scopes("user_info")
                .autoApprove(true)
                .redirectUris("http://localhost:8081/webui/login/oauth2/code/ataoge","http://localhost:8081/webui/login","http://localhost:8081/webui/signin");
    }

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
       endpoints.authenticationManager(authenticationManager)
                .tokenStore(tokenStore())
                //.userDetailsService()

                .accessTokenConverter(accessTokenConverter());
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        //converter.setKeyPair(this.keyPair);
        String privateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEpQIBAAKCAQEAuTiMFqKOMTaJ8/Y1bRmjrreIiuC4au/6eq1NiHKHFhEqEh7b\n" +
                "pySWzPoFsOKEw3KhYqiuHk4N1Gz9PnwbKwzSWMisiUnq/HCayqYlmSKQkvDGhUEP\n" +
                "rX5jCv+klSVqgZ28g6C9lni2dN86zko1RmWShhJkBfxUtRCc8iUJKYZrt4ZkUj0d\n" +
                "xe03dif5mTsuWzIPXdveQZHfWn+1iu1Zgn1IDBZ4RjqolcXJaJaIqjuJFy59xwWM\n" +
                "i2Ayn5TwoFEGwhbN6v6cvln3QoWOm1CI3b0HjY/gvCdl4tD00qPZypQNlcpDrlZJ\n" +
                "OZDijR1aFIrDHd+mG87q7rT+/8VrV/QXQEyJ5wIDAQABAoIBAQCV1A5OSRSo7qtN\n" +
                "c77oEDN+I+0KGppTtuhx0DrFw49O5HeZzOh2Hnz2NtHfsn0e9V1jR3wB+7XoPnnk\n" +
                "z9PSUT7enwYi0G6L4jL09s23QGSe2LJeHLEn8PMBdKaYF3o+e3CBMcfrLp65j9Is\n" +
                "CY9q8MNEPSA4T1PeXB/5KMhulNQR0f39mG8N5NeTdMedWGd3u9Rvl/HiExz5XoZb\n" +
                "P/LElBIzgG0vWYpK1H+qHEJ/dfQDvxzA47JG4sONwGk9Aa+y9brdOeslJHzCXJVp\n" +
                "7asmcXhv9Rozyqp4mhiu5iCdLe0eotgmatVpDPHBb+W7gnsXlgG8hI6gDrFqQpwN\n" +
                "hhSeZg8hAoGBAOZrgZWh4V14yPhlsmc5kkuknWKhY74pJaSbNG0yC4hhOIa7s+cY\n" +
                "EaIL/6XbW/FyTC18imcjQAhqkQbRHCz8Q06dE2yuIx7LZDD7HD2BTgeZfRf+EpVW\n" +
                "rRFlgsMtGKwLWPVyk2k5evrzuAHN6zlK2Fj5KZoGDBi7/wlo0qRJ4OVPAoGBAM3I\n" +
                "felnN4vMbGyEukA/3bp0cxT7c5VsIbu+7fa7hD/UMJUMmDCfMXioh30LgMi1EKs1\n" +
                "r4FWNwrJpj83Y/8spWk2WY47TyoZTsclDVbTCdH3MfCEzmN0xnFVZWQOEf5NzSDf\n" +
                "y27DTCiQyGPM7v2LSO30detpaVqAcf2vataUq5vpAoGBAKvAIp04RtX3fEW6+Bn9\n" +
                "TdDYaP/lsIVEAm0JyzBBh1smrI2xR83PoQUa0Hn+YjA8tA+Lr1ZlbgtX87YTFF9r\n" +
                "wXfNmXb+7eq8THg+FLS7tz/u5tGFbrCmJOa8tZVp/ePvqWV6++oJEGQSWmvt45GW\n" +
                "+mCHiLzoGQguyVFoMuqGrv39AoGBAI1rntR7odnKaCz/3jvvaEMOalReJmXnBRvQ\n" +
                "sBsjbVSsT6LvH9wyWz5Pm6Vc9Wl5vfXblDyvcm5QfJbvSyJ/nUG8Hzm3GsWU1OXZ\n" +
                "Wdx0dkg8uK5RpsEE7KfQhziGzujUsQdJpbX+M2WhcoXbvdazFTCrEyrwq32NzkkI\n" +
                "d8T2MSWZAoGAIyLP3imTelRsnuZjcH6vUKucunDSxcDKoi0/yoX8rG0b4t9prKvh\n" +
                "iI9tD1xNOmv8QhJ2PL+8wKB7x/oeRVrXljbBdxBD4CMMHPfnj3UB22Yqf6hecVQp\n" +
                "ygZ8QQGlI5M04niZgiV5wTAjHtqwa6B6Y/Ai8BXwXDENMwnHEEMmwmE=\n" +
                "-----END RSA PRIVATE KEY-----";

        converter.setSigningKey(privateKey);
        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuTiMFqKOMTaJ8/Y1bRmj\n" +
                "rreIiuC4au/6eq1NiHKHFhEqEh7bpySWzPoFsOKEw3KhYqiuHk4N1Gz9PnwbKwzS\n" +
                "WMisiUnq/HCayqYlmSKQkvDGhUEPrX5jCv+klSVqgZ28g6C9lni2dN86zko1RmWS\n" +
                "hhJkBfxUtRCc8iUJKYZrt4ZkUj0dxe03dif5mTsuWzIPXdveQZHfWn+1iu1Zgn1I\n" +
                "DBZ4RjqolcXJaJaIqjuJFy59xwWMi2Ayn5TwoFEGwhbN6v6cvln3QoWOm1CI3b0H\n" +
                "jY/gvCdl4tD00qPZypQNlcpDrlZJOZDijR1aFIrDHd+mG87q7rT+/8VrV/QXQEyJ\n" +
                "5wIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        converter.setVerifierKey(publicKey);

        /*
        Resource resource = new ClassPathResource("public.txt");


        try {
            publicKey = inputStream2String(resource.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }*/

        return converter;
    }

    private String inputStream2String(InputStream is) throws IOException
    {
        BufferedReader in = new BufferedReader(new InputStreamReader(is));
        StringBuilder builder = new StringBuilder();
        String line;
        while ((line = in.readLine())!=null) {
            builder.append(line);
        }
        return builder.toString();
    }


}
