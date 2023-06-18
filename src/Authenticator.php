<?php

namespace roaresearch\yii2\cognito;

use TeamGantt\Juhwit\{CognitoClaimVerifier, JwtDecoder, Models\UserPool};
use Yii;
use yii\filters\auth\AuthMethod;
use yii\web\UnauthorizedHttpException;

class Authenticator extends AuthMethod
{
    /**
     * The 'userModelClass' is a public string variable representing the fully qualified class name 
     * of the User model. This is necessary for the authentication process, as this class is used 
     * to instantiate User objects, retrieve existing users from the database, or register new users.
     *
     * By default, the 'userModelClass' is set to 'app\models\User'. However, depending on your 
     * application structure, you might need to modify this value. To use a different User model, 
     * simply assign the appropriate fully qualified class name to this variable.
     */
    public string $userModelClass = 'app\models\User';

    /**
     * The URL_TEMPLATE is a constant string that represents a URL template 
     * for the AWS Cognito identity provider service. It contains placeholders 
     * 'REGION' and 'USER_POOL_ID' which will be replaced by actual values at runtime.
     */
    public const URL_TEMPLATE = 'https://cognito-idp.REGION.amazonaws.com/USER_POOL_ID/.well-known/jwks.json';

    /**
     * The 'userPoolId' is a public string variable which represents the ID of the User Pool 
     * in AWS Cognito service. This value will replace the 'USER_POOL_ID' placeholder in the URL_TEMPLATE.
     */
    public string $userPoolId = '<userPoolId>';

    /**
     * The 'region' is a public string variable that represents the AWS region 
     * where the Cognito service is hosted. This value will replace the 'REGION' placeholder in the URL_TEMPLATE.
     */
    public string $region = '<region>';

    /**
     * The 'clientIds' is a public array which is designed to hold the client IDs 
     * related to the AWS Cognito service. This could be used to validate tokens or 
     * for other AWS service interactions.
     */
    public array $clientIds = ['clientIds'];

    /**
     * The 'pattern' is a public string variable used as a regex pattern. It is designed 
     * to validate bearer tokens in the 'Authorization' header of HTTP requests.
     * The pattern is specifically looking for JWT (JSON Web Token) structure.
     */
    public string $pattern = '/^Bearer\s+([\w\-_=]+\.[\w\-_=]+\.[\w\-_=]+)$/';
    
    /**
     * This function returns a URL. 
     *
     * The URL is constructed using a URL_TEMPLATE constant from the class.
     * This template contains placeholders 'REGION' and 'USER_POOL_ID' which 
     * are replaced by the current object's 'region' and 'userPoolId' properties respectively.
     *
     * The 'strtr' function is used to perform the replacements.
     *
     * @return string The constructed URL.
     */
    public function getUrl(): string 
    {
        return strtr(static::URL_TEMPLATE, ['REGION' => $this->region, 'USER_POOL_ID' => $this->userPoolId]);
    }

    /**
     * This method is used to authenticate a user based on a bearer token.
     *
     * First, it extracts the 'Authorization' header from the request. If the header exists and matches the
     * bearer token pattern, the JWT token is extracted from the header.
     *
     * The method then retrieves JSON Web Keys (JWKs) from Amazon Cognito and attempts to decode the JWT token
     * using these keys and the details of the user pool. The 'JwtDecoder' and 'CognitoClaimVerifier' classes 
     * are used for this purpose.
     *
     * If the JWT token is successfully decoded, it ensures the existence of the user based on Cognito and logs in 
     * the user into the application. The method then returns the user's identity.
     *
     * If an error occurs during the JWT token decoding, an error is logged and an UnauthorizedHttpException is thrown,
     * indicating the invalidity of the Cognito token.
     *
     * If the 'Authorization' header does not exist or does not match the pattern, the method simply returns null.
     *
     * @param mixed $user The user component that manages the user authentication status.
     * @param mixed $request The request component that contains request details.
     * @param mixed $response The response component that is used to send the HTTP response.
     *
     * @return mixed|null The authenticated user's identity or null if authentication is not successful.
     *
     * @throws UnauthorizedHttpException if the JWT token is invalid.
     */
    public function authenticate($user, $request, $response)
    {
        $authHeader = $request->getHeaders()->get('Authorization');
        if ($authHeader !== null && preg_match($this->pattern, $authHeader, $matches)) {
            $tokenString = $matches[1];
            
            Yii::info('Send Amazon Cognito connection');
            $jwk = json_decode($this->getJwks(), true);
            Yii::info('Amazon Cognito received');

            $decoder = new JwtDecoder(
                new CognitoClaimVerifier(
                    new UserPool(
                        $this->userPoolId,
                        $this->clientIds,
                        $this->region,
                        $jwk
                    )
                )
            );
            try {
                
                Yii::info('decode token');
                $token = $decoder->decode($tokenString);
                Yii::info('token decoded');

                $identity = $this->ensureUserByCognito($token);
                $user->login($identity);
                return $identity;
            } catch (\Exception $e) {
                Yii::error('invalid token');
                throw new UnauthorizedHttpException('Cognito token invalid', 0, $e);
            }
        }
        return null;
    }

    /**
     * This method is used to ensure the existence of a user based on the given JWT token from Cognito.
     *
     * First, it attempts to find the user by the 'username' claim in the token. If the user exists, it 
     * is returned immediately.
     *
     * If no user is found with the given username, the method proceeds to register a new user with the 
     * information provided in the token, and then returns the newly registered user.
     *
     * @param object $token The JWT token from Cognito which contains the user's information.
     *
     * @return User The user found or created based on the token's 'username' claim.
     */
    public function ensureUserByCognito($token)
    {
        $userClass = $this->userModelClass;
        return $userClass::findByUsername($token->getClaim('username')) ?:
            $this->registerUser($token);
    }

    /**
     * This method is used to register a new user based on the provided JWT token from Cognito.
     *
     * It extracts the necessary user information from the token, such as username, 
     * email etc., and creates a new user in the application's user system.
     *
     * @param object $token The JWT token from Cognito which contains the user's information.
     *
     * @return User The newly registered user.
     * @todo Register new user
     */
    public function registerUser($token)
    {
        $user = new $this->userModelClass;
        $user->username = $token->getClaim('username');
        $user->save();
        return $user;
        // etc
    }

    /**
     * This method is used to fetch JWKS (JSON Web Key Set) used for verifying incoming JWTs.
     *
     * The method first checks if the JWKS exists in the application's cache. If it does and the cached version is 
     * less than 60 minutes old, it uses the cached version.
     *
     * If the cached JWKS is more than 60 minutes old or doesn't exist, it fetches the JWKS from the URL provided by 
     * the 'getUrl' method, stores it in the cache with the current time, and then returns the fetched JWKS.
     *
     * @return string The JSON Web Key Set.
     */
    public function getJwks()
    {
        $cache = Yii::$app->cache;
        // Check if JWKS exists in cache
        if ($cache->exists('jwks')) {
            // Get the time when it was last stored
            $lastUpdateTime = $cache->get('jwks_time');
    
            // Check if more than 60 minutes have passed since the last update
            if (time() - $lastUpdateTime >= 60 * 60) {
                // More than 60 minutes have passed, so we need to update the JWKS
                $jwks = file_get_contents($this->getUrl());
                $cache->set('jwks', $jwks);
                $cache->set('jwks_time', time());
            } else {
                // Less than 60 minutes have passed, so we can use the version in cache
                $jwks = $cache->get('jwks');
            }
        } else {
            // JWKS doesn't exist in the cache, so we need to fetch and store it
            $jwks = file_get_contents($this->getUrl());
            $cache->set('jwks', $jwks);
            $cache->set('jwks_time', time());
        }
    
        return $jwks;
    }
}
