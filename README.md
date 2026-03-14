Strictly to be written in a way where u acronymishly abbreviate only if it is a abbreviation that most programmers use VERY OFTEN, obviously we'll use acronyms for things like sha and encryption spec names, but I absolutely hate goin through old projects written in C and having to constantly google what each abbrv means, sick of that stupid shit, slowing me artificially down, not allowed here, so if u using names like: 
    abbrv for name:
        Fq	FiniteFieldElement
        recip	reciprocal
        PolynomialRq	PolynomialRingElement
        Small	SmallCoefficient
        fe_add	field_element_add
        fe_sub	field_element_subtract
        fe_mul	field_element_multiply
        fe_sq	field_element_square
        fe_inv	field_element_inverse
        fe_from_bytes	field_element_from_bytes
        fe_to_bytes	field_element_to_bytes
        cswap	conditional_swap
        Sntrup761x25519Sha512	Sntrup761X25519Sha512KeyEncapsulationMechanism
        to_rq	to_ring_element
        from_rq	from_ring_element
        RQ_BYTES	RING_ELEMENT_BYTES
        P	PRIME_DEGREE
        Q	FIELD_MODULUS
        W	WEIGHT

I am interested in this project being readable to programmers, not only the ones from them who already know that rq stands for ring element bytes or only mathematicians who know that fq oBvIoUslY stands for finite field element oF cOurSe or someshit -_-

none the less every crypto impl will have a .tex file with the concise math that that crypto impl should be sort of doin, u can pdftex <file> that one for help with dev/wanting to understand

