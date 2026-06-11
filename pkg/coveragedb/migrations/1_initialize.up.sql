CREATE TABLE files (
    session text,
    manager text,
    filepath text,
    instrumented bigint,
    covered bigint,
    linesinstrumented bigint[],
    hitcounts bigint[],
    PRIMARY KEY (session, manager, filepath)
);

CREATE TABLE functions (
    session text,
    filepath text,
    funcname text,
    lines bigint[],
    PRIMARY KEY (session, filepath, funcname)
);

CREATE TABLE merge_history (
    namespace text,
    repo text,
    duration bigint,
    dateto date,
    session text,
    "time" timestamptz,
    "commit" text,
    totalrows bigint,
    PRIMARY KEY (namespace, repo, duration, dateto)
);

CREATE INDEX merge_history_session ON merge_history (session);

CREATE TABLE file_subsystems (
    namespace text,
    filepath text,
    subsystems text[],
    PRIMARY KEY (namespace, filepath)
);
