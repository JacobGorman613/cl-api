# USAGE:
    - Dependencies (this is what I had to do to get the package to work on a fresh build of Ubuntu 20.05)
        - Python 3.8 is required (specifically for negative powers modulo n to be supported in pow(a,b,n))
        - pip3 (sudo apt install python3-pip) (for installation of other dependencies)
        - pycrypto (pip3 install pycrypto)
            - on Unix based systems with Python 3.8 or later you may get an error message with cause
            - File ".../python3.8/site-packages/Crypto/Random/_UserFriendlyRNG.py", line 77, in collect t = time.clock()
            - need to change this time.clock() to time.time() in _UserFriendlyRNG.py if you are on a Unix based system
            - I need to find a better isprime method but this is the best fix for now (other packages broke a lot so I will try to fix this later)
    - Running 
        - python3 demo.py

# DESCRIPTION:
    This API implements deanonymizable credentials as described by Camenisch and Lysyanskaya. Manual usage is supported
    but it is recommended to use the ca and idp schedulers to implement the CA and IDP as described in our diagrams.
# TODO:
    - Main Functionality!
        - add store id_u // this happens somewhere
    - Decision Points
        - should we move vf_id to same step as nym_gen_1?
    - Usability
        - do deanon messages need a session id?
        - replace [] with .get() so we can do error handling?
        - move all the methods in constants that are used in the demo only
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
    - Security
        - After parseing msg['type'] delete all fields from msg that wouldn't be present in that type (write now we only check that the ones that should be there are correct)