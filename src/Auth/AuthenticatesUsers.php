<?php

namespace hairyLemonLtd\LaravelCognitoAuth\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Validation\ValidationException;
use hairyLemonLtd\LaravelCognitoAuth\Exceptions\NoLocalUserException;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use hairyLemonLtd\LaravelCognitoAuth\CognitoClient;

trait AuthenticatesUsers
{
    public $cognito_done = false;
    public $cognito;
    public $cognito_attributes = [];


    /**
     * Attempt to log the user into the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function attemptLogin(Request $request)
    {
        try {
            $response = $this->guard()->attempt($this->credentials($request), $request->has('remember'));
        } catch (NoLocalUserException $e) {
            $response = $this->createLocalUser($this->credentials($request));
        }

        return $response;
    }

    /**
     * Create a local user if one does not exist.
     *
     * @param  array  $credentials
     * @return mixed
     */
    protected function createLocalUser($credentials)
    {
        return true;
    }

    /**
     * @param Request $request
     */
    public function login(Request $request)
    {
        $this->validateLogin($request);

        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        try {
            if ($this->attemptLogin($request)) {
                return $this->sendLoginResponse($request);
            }
        } catch (CognitoIdentityProviderException $c) {
            return $this->sendFailedCognitoResponse($c);
        } catch (\Exception $e) {
            return $this->sendFailedLoginResponse($request);
        }

        return $this->sendFailedLoginResponse($request);
    }

    /**
     * @param CognitoIdentityProviderException $exception
     */
    private function sendFailedCognitoResponse(CognitoIdentityProviderException $exception)
    {
        throw ValidationException::withMessages([
            $this->username() => $exception->getAwsErrorMessage(),
        ]);
    }

    public function setCognito($cognito_user): void
    {
        if ($this->cognito_done) {
            return;
        }

        $uuid = $this->attributes['uuid'];

        // get all of teh attrubutes and fill in cognito_attributes
        $userAttributes = $cognito_user->get('UserAttributes');

        foreach ($userAttributes as $userAttribute) {
            $this->cognito_attributes[$userAttribute['Name']] = $this->transformCognitoValue($userAttribute['Value']);
        }

        $this->attributes['email'] = $this->cognito_attributes['email'];

        // match session TTL + 5 min
        Cache::put('cognito_attributes_'.$uuid, $this->cognito_attributes, ( (session()->getSessionConfig()['lifetime'] * 60) + 300) );

        $this->cognito_done = true;

    }
    // called on retrieved event
    private function setupCognito(): void
    {
        if ($this->cognito_done ||  is_array($this->cognito_attributes) ) {
            return;
        }

        $this->cognito_attributes = Cache::get('cognito_attributes_'.$this->attributes['uuid']);

        if(! $this->cognito_attributes ){
            abort(401);
        }

        $this->attributes['email'] = $this->cognito_attributes['email'];
        $this->cognito_done = true;
    }
}
