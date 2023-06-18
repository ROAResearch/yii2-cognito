# Yii2 Cognito

This Yii2 extension provides a Cognito Authenticator.

## Requirements

- PHP 8.2 or higher
- [Yii2](https://www.yiiframework.com/) ~2.0.48
- [teamgantt/juhwit](https://github.com/teamgantt/juhwit)

## Installation

To install the package, you need to install [composer](http://getcomposer.org/download/) and then run the following command:


## Usage

Add `Authenticator` to the `authMethods` section of your `authenticator` component:

```php
'authenticator' => [
    'class' => \yii\filters\CompositeAuth::class,
    'oauth2Module' => $this->getOauth2Module(),
    'authMethods' => [
        [
            'class' => \roaresearch\yii2\cognito\Authenticator::class,
            'userModelClass' => 'common\models\User',
            'userPoolId' => '<userPoolId>',
            'region' => '<region>',
            'clientIds' => ['clientIds'],
        ],
        [
            'class' => \yii\filters\auth\HttpBearerAuth::class,
        ],
        [
            'class' => \yii\filters\auth\QueryParamAuth::class,
            // !Important, GET request parameter to get the token.
            'tokenParam' => 'accessToken',
        ],
    ],
]
```

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/ROAResearch/yii2-roa/tags).

Considering [SemVer](http://semver.org/) for versioning rules 9, 10 and 11 talk about pre-releases, they will not be used within the ROAResearch.

## Authors

* [**Angel Guevara**](https://github.com/Faryshta) - Initial work
* [**Carlos Llamosas**](https://github.com/neverabe) - Initial work

See also the list of [contributors](https://github.com/ROAResearch/yii2-roa/graphs/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
