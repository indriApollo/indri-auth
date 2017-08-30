create table users(
    uid integer primary key autoincrement,
    username varchar(255) not null,
    hash varchar(255) not null,
    CONSTRAINT username_unique UNIQUE (username)
);

create table tokens(
    uid integer primary key,
    token varchar(255),
    validity integer,
    CONSTRAINT token_unique UNIQUE (token)
);

create table usersdata(
    uid integer primary key,
    userdata text
);

create table passreset(
    uid integer primary key,
    token varchar(255),
    validity integer,
    CONSTRAINT token_unique UNIQUE (token)
);

create table trustedurls(
    tuid integer primary key autoincrement,
    domain varchar(255) not null,
    reseturi text not null
);
