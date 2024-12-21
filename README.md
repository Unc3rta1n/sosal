
# Что было сделано

## Установка зависимости

```bash
composer require laminas/laminas-authentication
```

## Изменения в конфигурации PHP

В файле `/etc/php/8.3/apache2/php.ini` были внесены следующие изменения:

```ini
session.save_path = "/var/www/data/session"
session.use_strict_mode = 1
session.use_cookies = 1
session.cookie_lifetime = 86400
session.cookie_httponly = 1
```

Возможно, были внесены другие изменения, но они не задокументированы.

## Конфигурация сессий в `local.php`

В файле `/var/www/config/autoload/local.php` добавлена конфигурация для сессий:

```php
'session_config' => [
    'cookie_secure' => false, // Убираем опцию secure
    'cookie_httponly' => true, // Устанавливаем HttpOnly
    'cookie_samesite' => 'Lax', // Устанавливаем SameSite
    'cookie_lifetime' => 60 * 60 * 1, // 1 час
    'gc_maxlifetime' => 60 * 60 * 24 * 30, // 30 дней
],
'session_manager' => [
    'validators' => [
        \Laminas\Session\Validator\RemoteAddr::class,
        \Laminas\Session\Validator\HttpUserAgent::class,
    ],
],
'session_storage' => [
    'type' => \Laminas\Session\Storage\SessionArrayStorage::class,
],
```

## Добавление модулей в `modules.config.php`

В файле `/var/www/config/modules.config.php` добавлены следующие модули:

```php
'Laminas\Session',
'Laminas\Mvc\Plugin\FlashMessenger',
```

## Добавление метода для запуска `SessionManager`

В файле `/var/www/module/Application/src/Module.php` добавлен метод `onBootstrap`:

```php
<?php

declare(strict_types=1);
namespace Application;

use Laminas\Mvc\MvcEvent;
use Laminas\Session\SessionManager;
class Module
{
    public function getConfig(): array
    {
        /** @var array $config */
        $config = include __DIR__ . '/../config/module.config.php';
        return $config;
    }
    /**
     * Метод, вызываемый при запуске приложения
     *
     * @param MvcEvent $e
     * @return void
     */
    public function onBootstrap(MvcEvent $e)
    {
        $application = $e->getApplication();
        $serviceManager = $application->getServiceManager();

        // Запуск сессии
        $sessionManager = $serviceManager->get(SessionManager::class);
        $sessionManager->start();
    }
}

```

## Добавление маршрутов в `module.config.php`

В файле `/var/www/module/Application/config/module.config.php` добавлены маршруты:

```php
'login' => [
    'type' => 'Literal',
    'options' => [
        'route' => '/login',
        'defaults' => [
            'controller' => Controller\AuthController::class,
            'action' => 'login',
        ],
    ],
],
'logout' => [
    'type' => 'Literal',
    'options' => [
        'route' => '/logout',
        'defaults' => [
            'controller' => Controller\AuthController::class,
            'action' => 'logout',
        ],
    ],
],
'protected' => [
    'type' => 'Literal',
    'options' => [
        'route' => '/protected',
        'defaults' => [
            'controller' => Controller\ProtectedController::class,
            'action' => 'index',
        ],
    ],
],
```

Также добавлены фабрики:

```php
Controller\AuthController::class => Controller\Factory\AuthControllerFactory::class,
Controller\ProtectedController::class => Controller\Factory\ProtectedControllerFactory::class,
```

## Фабрики контроллеров

### `AuthControllerFactory.php`

```php
<?php
namespace Application\Controller\Factory;

use Interop\Container\ContainerInterface;
use Zend\ServiceManager\Factory\FactoryInterface;
use Application\Controller\AuthController;

class AuthControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, 
                     $requestedName, array $options = null)
    {
        $entityManager = $container->get('doctrine.entitymanager.orm_default');
        return new AuthController($entityManager);
    }
}
```

### `ProtectedControllerFactory.php`

```php
<?php
namespace Application\Controller\Factory;

use Interop\Container\ContainerInterface;
use Zend\ServiceManager\Factory\FactoryInterface;
use Application\Controller\ProtectedController;

class ProtectedControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, 
                     $requestedName, array $options = null)
    {
        $entityManager = $container->get('doctrine.entitymanager.orm_default');
        return new ProtectedController($entityManager);
    }
}
```

## Контроллеры

### `AuthAdapter.php`

```php
<?php
namespace Application\Controller;

use Laminas\Authentication\Adapter\AdapterInterface;
use Laminas\Authentication\Result;
use Doctrine\ORM\EntityManager;
use Application\Entity\Account;

class AuthAdapter implements AdapterInterface
{
    private $entityManager;
    private $username;
    private $password;

    public function __construct(EntityManager $entityManager, $username, $password)
    {
        $this->entityManager = $entityManager;
        $this->username = $username;
        $this->password = $password;
    }

    public function authenticate()
    {
        error_log("AuthAdapter: Username=$this->username, Password=$this->password");
        $user = $this->entityManager->getRepository(Account::class)
            ->findOneBy(['username' => $this->username]);
        if ($user) {
            error_log("AuthAdapter: User found. User ID=" . $user->getId() . ", Username=" . $user->getUsername());
        } else {
            error_log("AuthAdapter: User not found for username=$this->username");
        }
        if ($user && $user->verifyPassword($this->password)) {
            error_log("AuthAdapter: Password verified successfully for user ID=" . $user->getId());
            return new Result(Result::SUCCESS, $user);
        } else {
            if ($user) {
                error_log("AuthAdapter: Password verification failed for user ID=" . $user->getId() . ". Provided password=$this->password, hashed password=" . $user->getPassword());
            }
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, null, ['Invalid credentials.']);
        }
    }
}
```

### `AuthController.php`

```php
<?php
namespace Application\Controller;

use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\ViewModel;
use Laminas\Authentication\AuthenticationService;
use Application\Form\LoginForm;
use Doctrine\ORM\EntityManager;
use Application\Controller\AuthAdapter;

class AuthController extends AbstractActionController
{
    private $entityManager;

    public function __construct(EntityManager $entityManager) 
    {
        $this->entityManager = $entityManager;
    }

    public function loginAction()
    {
        $form = new LoginForm();
        $request = $this->getRequest();

        if ($request->isPost()) {
            $data = $request->getPost();
            $form->setData($data);

            if ($form->isValid()) {
                $data = $form->getData();
                $username = $data['username'];
                $password = $data['password'];

                $authAdapter = new AuthAdapter($this->entityManager, $username, $password);
                $authService = new AuthenticationService();

                $result = $authService->authenticate($authAdapter);

                if ($result->isValid()) {
                    $authService->getStorage()->write($result->getIdentity());
                    error_log("AuthController: Identity saved to session");
                    return $this->redirect()->toRoute('protected');
                } else {
                    error_log("LoginAction: Authentication failed");
                    foreach ($result->getMessages() as $message) {
                        $this->flashMessenger()->addErrorMessage($message);
                        error_log("LoginAction: Authentication error message: $message");
                    }
                }
            } else {
                error_log("LoginAction: Form is invalid");
            }
        }

        return new ViewModel(['form' => $form]);
    }

    public function logoutAction()
    {
        $authService = new AuthenticationService();
        if ($authService->hasIdentity()) {
            $authService->clearIdentity();
            error_log("AuthController: Identity cleared from session");
        }
        return $this->redirect()->toRoute('login');
    }
}
```

### `ProtectedController.php`

```php
<?php
namespace Application\Controller;

use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\ViewModel;
use Laminas\Authentication\AuthenticationService;
use Doctrine\ORM\EntityManager;

class ProtectedController extends AbstractActionController
{
    private $entityManager;

    public function __construct(EntityManager $entityManager) 
    {
        $this->entityManager = $entityManager;
    }

    public function indexAction()
    {
        // Создаем экземпляр AuthenticationService
        $authService = new AuthenticationService();
    
        if (!$authService->hasIdentity()) {
            error_log("ProtectedController: Identity not found in session, referer: " . $_SERVER['HTTP_REFERER']);
            return $this->redirect()->toRoute('login');
        } else {
            error_log("ProtectedController: Identity found in session");
        }
    
        // Получаем идентификацию пользователя
        $user = $authService->getIdentity();
    
        // Передаем имя пользователя в представление
        return new ViewModel([
            'account' => $user->getUsername(), // Предполагаем, что у вас есть метод getUsername()
        ]);
    }
}
```

## Форма входа

### `LoginForm.php`

```php
<?php

namespace Application\Form;

use Laminas\Form\Form;
use Laminas\Form\Element;
use Laminas\InputFilter\InputFilter;

class LoginForm extends Form
{
    public function __construct()
    {
        parent::__construct('login-form');

        $this->add([
            'name' => 'username',
            'type' => Element\Text::class,
            'options' => [
                'label' => 'Username',
            ],
        ]);

        $this->add([
            'name' => 'password',
            'type' => Element\Password::class,
            'options' => [
                'label' => 'Password',
            ],
        ]);

        $this->add([
            'name' => 'submit',
            'type' => Element\Submit::class,
            'attributes' => [
                'value' => 'Login',
            ],
        ]);

        $this->setInputFilter($this->createInputFilter());
    }

    private function createInputFilter()
    {
        $inputFilter = new InputFilter();

        $inputFilter->add([
            'name' => 'username',
            'required' => true,
            'filters' => [
                ['name' => 'StringTrim'],
            ],
            'validators' => [
                ['name' => 'StringLength', 'options' => ['min' => 3, 'max' => 255]],
            ],
        ]);

        $inputFilter->add([
            'name' => 'password',
            'required' => true,
            'filters' => [
                ['name' => 'StringTrim'],
            ],
            'validators' => [
                ['name' => 'StringLength', 'options' => ['min' => 6, 'max' => 255]],
            ],
        ]);

        return $inputFilter;
    }
}
```

## Сущность `Account`

### `Account.php`

```php
<?php
namespace Application\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity
 * @ORM\Table(name="accounts")
 */
class Account
{
    /**
     * @ORM\Id
     * @ORM\GeneratedValue
     * @ORM\Column(type="integer")
     */
    private $id;

    /**
     * @ORM\Column(type="string", length=255, unique=true)
     */
    private $username;

    /**
     * @ORM\Column(type="string", length=255)
     */
    private $password;

    // Геттеры и сеттеры

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(string $username): self
    {
        $this->username = $username;
        return $this;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(string $password): self
    {
        $this->password = $password; // Сохраняем пароль в открытом виде
        return $this;
    }

    // Метод для проверки пароля
    public function verifyPassword(string $password): bool
    {
        return $this->password === $password; // Простое сравнение паролей
    }
}
```

## Представления

### `login.phtml`

```html
<h1>Login</h1>

<?php if (!empty($messages)): ?>
    <ul>
        <?php foreach ($messages as $message): ?>
            <li><?= $message ?></li>
        <?php endforeach; ?>
    </ul>
<?php endif; ?>

<form method="post">
    <label for="username">Username:</label>
    <input type="text" name="username" id="username">
    <br>
    <label for="password">Password:</label>
    <input type="password" name="password" id="password">
    <br>
    <button type="submit">Login</button>
</form>
```

### `index.phtml`

```html
<h1>Защищенная страница</h1>

<p>Добро пожаловать, <?= $this->escapeHtml($account) ?>!</p>

<a href="<?= $this->url('logout') ?>">Выйти</a>
```
```