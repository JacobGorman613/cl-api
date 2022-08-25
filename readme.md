DESCRIPTION:
    This API implements deanonymizable credentials as described by Camenisch and Lysyanskaya. Manual usage is supported
    but it is recommended to use the ca and idp schedulers to implement the CA and IDP as described in our diagrams.
TODO:
    - Main Functionality!
        - add store id_u
    - Usability
        - do deanon messages need a session id?
        - replace [] with .get() so we can do error handling?
    - Documentation
        - improve the last diagram in diagrams
            - it was rushed to finish before a meeting and is highly informal   
        - make this into a formatted readme with instructions
        - make an updated latex documentation
        - document the zkp stuff (elsewhere)
    - ZKP
        - add range constraints to zkp
        - find correct values for constants
        - s_u bug