<?php

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException as HttpClientException;

class sspmod_go5auth_Auth_Source_LoggedUser extends SimpleSAML_Auth_Source
{
    /**
     * @var HttpClient
     */
    private $httpClient;

    public function __construct(array $info, array $config)
    {
            parent::__construct($info, $config);

            $this->httpClient = new HttpClient;
    }

    public function authenticate(&$state)
    {
        if (!array_key_exists('access_token', $_REQUEST)
            && !array_key_exists('HTTP_AUTHORIZATION', $_SERVER)
        ) {
            header('HTTP/1.1 401 Unauthorized');
            echo 'go5auth | error: access_token is required';
            exit;
        }

        $metadataSP = $state['SPMetadata'];
        $metadataIDP = $state['IdPMetadata'];

        if (!$metadataSP['enabled'] || !$metadataIDP['enabled'] || $metadataSP['platformId'] != $metadataIDP['platformId']) {
            header('HTTP/1.1 401 Unauthorized');
            echo 'go5auth | error: invalid platform idp';
            exit;
        }

        $accessToken = isset($_REQUEST['access_token'])
            ? $_REQUEST['access_token']
            : trim(substr($_SERVER['HTTP_AUTHORIZATION'], 7));

        SimpleSAML_Logger::debug('go5auth | access_token: ' . $accessToken);
        $userInfo = $this->getUserInfo($accessToken);

        if ($userInfo->data->attributes->status !== 'active' || $userInfo->data->attributes->{'login-enabled'} !== true) {
            header('HTTP/1.1 403 Forbidden');
            echo 'go5auth | error: inactive user';
            exit;
        }

        $userAttributes = [];
        $userInfoAttributes = $userInfo->data->attributes;
        $userAttributesMapping = $metadataSP['UserAttributesMapping'];

        if (is_array($userAttributesMapping) && !empty($userAttributesMapping)) {
            foreach ($userAttributesMapping as $mappedAttributeKey => $mappedAttributeValue) {
                $userAttributes[$mappedAttributeValue] = isset($userInfoAttributes->$mappedAttributeKey)
                    ? $userInfoAttributes->$mappedAttributeKey
                    : '';
            }
        } else {
            $userAttributes = [
                'email' => $userInfoAttributes->email,
                'employee-id' => $userInfoAttributes->{'employee-id'},
                'document' => $userInfoAttributes->{'document'},
                'document-type' => $userInfoAttributes->{'document-type'},
                'name' => $userInfoAttributes->{'name'},
                'last-name' => $userInfoAttributes->{'last-name'},
            ];
        }

        $state['Attributes'] = SimpleSAML_Utilities::parseAttributes($userAttributes);

        SimpleSAML_Auth_Source::completeAuth($state);
    }

    private function getUserInfo($token)
    {
        try {
            $tokenResponse = $this->httpClient->get(URL_PREFIX . '/oauth/token?access_token=' . $token);
            $tokenInfo  = json_decode($tokenResponse->getBody()->getContents());
            $userResponse = $this->httpClient->get(
                BASE_URI_USER_SDK . '/users/' . $tokenInfo->user_id, [
                'headers' => [
                    'x-go5-platform-id' => $tokenInfo->platform_id,
                    'x-app-sdk' => 1,
                ]]);

            return json_decode($userResponse->getBody()->getContents());

        } catch (HttpClientException $e) {
            header('HTTP/1.1 401 Unauthorized');
            echo 'go5auth | error: invalid access_token';
            exit;
        }
    }
}
