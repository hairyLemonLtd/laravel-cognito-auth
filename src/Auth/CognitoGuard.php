<?php

namespace hairyLemonLtd\LaravelCognitoAuth\Auth;

use App\Models\User;
use Aws\Result;
use Illuminate\Auth\SessionGuard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Session\Session;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\StatefulGuard;
use Symfony\Component\HttpFoundation\Request;
use Illuminate\Contracts\Auth\Authenticatable;
use hairyLemonLtd\LaravelCognitoAuth\CognitoClient;
use hairyLemonLtd\LaravelCognitoAuth\Exceptions\InvalidUserModelException;

class CognitoGuard extends SessionGuard implements StatefulGuard
{
    /**
     * @var CognitoClient
     */
    protected $client;

    /**
     * CognitoGuard constructor.
     * @param string $name
     * @param CognitoClient $client
     * @param UserProvider $provider
     * @param Session $session
     * @param null|Request $request
     */
    public function __construct(
        string $name,
        CognitoClient $client,
        UserProvider $provider,
        Session $session,
        ?Request $request = null
    ) {
        $this->client = $client;

        //info(__METHOD__ .' client: '.$client->poolId);

        parent::__construct($name, $provider, $session, $request);
    }

    /**
     * @param mixed $user
     * @param array $credentials
     * @return bool
     * @throws InvalidUserModelException
     */
    protected function hasValidCredentials($user, $credentials)
    {
        /** @var Result $response */

        //info(__METHOD__ . ' Client', (array) $this->client);
        $client = \App\Models\User::getCognitoClient($credentials['email']);

        $result = $client->authenticate($credentials['email'], $credentials['password']);

        //dd($result);
        //info(__METHOD__.' cognito result ', ['cognito result:::' => $result]);

        // Only create the user if single sign on is activated in the project
        if (config('cognito.use_sso') && $result !== false && $user === null) {
            //$user = $this->createUser($credentials['email']); no
        }

        if ($result && $user instanceof Authenticatable) {
            return true;
        }

        // failures bubule up from authenticate method
        // so we are auth @ cognito from here
        return false;
    }

    /**
     * @param $email
     * @return Model
     * @throws InvalidUserModelException
     */
    private function createUser($email)
    {
        /** @var Result $userResult */
        $userResult = $this->client->getUser($email);
        $userAttributes = count($userResult->get('UserAttributes')) > 0 ? $userResult->get('UserAttributes') : [];
        $userFields = config('cognito.sso_user_fields');
        $userModel = config('cognito.sso_user_model');
        /** @var Model $user */
        $user = new $userModel;

        if (! $user instanceof Model) {
            throw new InvalidUserModelException('User model does not extend Eloquent Model class.');
        }

        foreach ($userAttributes as $userAttribute) {
            $name = $userAttribute['Name'];
            $value = $userAttribute['Value'];

            if (in_array($name, $userFields)) {
                $user->$name = $value;
            }
        }

        $user->save();

        return $user;
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @param  bool   $remember
     * @throws
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {

        $this->fireAttemptEvent($credentials, $remember);

        //logger()->error('start attempt w ' .$this->client->poolId);

        $client = \App\Models\User::getCognitoClient($credentials['email']);

        if($cognitoUser = $client->getUser($credentials['email'])){
            $uuid = $cognitoUser->get('Username');

            // special !
            $user = User::withoutEvents(function () use ($uuid) {
                return User::where('uuid', $uuid)->first();
            });

            if (! $user) {
                return false;
            }

            $user->setCognito($cognitoUser);

            $this->lastAttempted = $user;

            // If an implementation of UserInterface was returned, we'll ask the provider
            // to validate the user against the given credentials, and if they are in
            // fact valid we'll log the users into the application and return true.
            if ($this->hasValidCredentials($user, $credentials)) {
                $this->login($user, $remember);

                return true;
            }
        } // uuid or email


        // If the authentication attempt fails we will fire an event so that the user
        // may be notified of any suspicious attempts to access their account from
        // an unrecognized user. A developer may listen to this event as needed.
        $this->fireFailedEvent($user, $credentials);

        return false;
    }
}
