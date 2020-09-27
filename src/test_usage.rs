mod test {
    use crate::secrets::Secrets;

    static CONSUMER_KEY: &str = "<CONSUMER_KEY>";
    static CONSUMER_SECRET: &str = "<CONSUMER_SECRET>";
    static TOKEN: &str = "<ACCESS_TOKEN>";
    static TOKEN_SECRET: &str = "<ACCESS_TOKEN>";

    #[test]
    fn test_secret_builder() {
        let secret = Secrets::new(CONSUMER_KEY, CONSUMER_SECRET);
        println!("{:?}", secret);
        let secret_with_token =
            Secrets::new(CONSUMER_KEY, CONSUMER_SECRET).token(TOKEN, TOKEN_SECRET);
        println!("{:?}", secret_with_token);
    }
}
