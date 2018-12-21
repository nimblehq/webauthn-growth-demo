## A MFA demo app, including WebAuthn

### Usage

- Clone the repository

`git clone git@github.com:nimblehq/webauthn-growth-demo.git`

- Make sure you have set your $GOPATH, dep properly.
- Run: `$ cd app && go get . && dep ensure && go run .`

### With Docker:
- Run: `$ docker build -t webauthn-demo . && docker run -d -p 8080:8080 -it webauthn-demo -p :8080`

## License

This project is Copyright (c) 2014-2018 Nimble. It is free software,
and may be redistributed under the terms specified in the [LICENSE] file.

[LICENSE]: /LICENSE

## About

![Nimble](https://assets.nimblehq.co/logo/dark/logo-dark-text-160.png)

This project is maintained and funded by Nimble.

We love open source and do our part in sharing our work with the community!
See [our other projects][community] or [hire our team][hire] to help build your product.

[community]: https://github.com/nimblehq
[hire]: https://nimblehq.co/