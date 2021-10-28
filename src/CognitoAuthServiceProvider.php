<?php

namespace hairyLemonLtd\LaravelCognitoAuth;

use Illuminate\Support\Arr;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use hairyLemonLtd\LaravelCognitoAuth\Auth\CognitoGuard;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Laravel\Fortify\Fortify;

use Illuminate\Contracts\Auth\StatefulGuard;

class CognitoAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/cognito.php' => config_path('cognito.php'),
        ], 'config');

        $this->publishes([
            __DIR__.'/Resources/views' => resource_path('views/vendor/hairylemon-ltd/laravel-cognito-auth'),
        ], 'views');

        $this->publishes([
            __DIR__.'/Resources/lang' => resource_path('lang/vendor/hairylemon-ltd/laravel-cognito-auth'),
        ], 'lang');

        $this->app->singleton(CognitoClient::class, function (Application $app) {
            $config = [
                'region'      => config('cognito.region'),
                'version'     => config('cognito.version'),
            ];

            $credentials = config('cognito.credentials');

            if (! empty($credentials['key']) && ! empty($credentials['secret'])) {
                $config['credentials'] = Arr::only($credentials, ['key', 'secret', 'token']);
            }

            return new CognitoClient(
                new CognitoIdentityProviderClient($config),
                config('cognito.app_client_id'),
                config('cognito.app_client_secret'),
                config('cognito.user_pool_id')
            );
        });

//        Fortify::authenticateUsing(function (Request $request) {
//            $user = User::where('email', $request->email)->first();
//
//            if ($user && Hash::check($request->password, $user->password)) {
//                return $user;
//            }
//        });


        $this->app['auth']->extend('cognito', function (Application $app, $name, array $config) {
            $guard = new CognitoGuard(
                $name,
                $client = $app->make(CognitoClient::class),
                $app['auth']->createUserProvider($config['provider']),
                $app['session.store'],
                $app['request']
            );

            $guard->setCookieJar($this->app['cookie']);
            $guard->setDispatcher($this->app['events']);
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });

        $this->loadRoutesFrom(__DIR__.'/routes.php');
        $this->loadViewsFrom(__DIR__.'/Resources/views', 'hairylemon-ltd/laravel-cognito-auth');
        $this->loadTranslationsFrom(__DIR__.'/Resources/lang', 'hairylemon-ltd/laravel-cognito-auth');
    }

    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/cognito.php', 'cognito');
    }
}
