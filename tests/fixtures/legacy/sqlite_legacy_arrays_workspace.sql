BEGIN;

CREATE TABLE projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    color TEXT
);

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    config TEXT,
    datasets TEXT,
    status TEXT,
    project_id TEXT
);

CREATE TABLE pipelines (
    pipeline_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    name TEXT NOT NULL,
    expanded_config TEXT,
    generator_choices TEXT,
    dataset_name TEXT NOT NULL,
    dataset_hash TEXT,
    status TEXT,
    best_val REAL,
    best_test REAL,
    metric TEXT
);

CREATE TABLE chains (
    chain_id TEXT PRIMARY KEY,
    pipeline_id TEXT NOT NULL,
    steps TEXT NOT NULL,
    model_step_idx INTEGER NOT NULL,
    model_class TEXT NOT NULL,
    preprocessings TEXT,
    model_name TEXT,
    metric TEXT,
    task_type TEXT,
    best_params TEXT,
    dataset_name TEXT
);

CREATE TABLE predictions (
    prediction_id TEXT PRIMARY KEY,
    pipeline_id TEXT NOT NULL,
    chain_id TEXT,
    dataset_name TEXT NOT NULL,
    model_name TEXT NOT NULL,
    model_class TEXT NOT NULL,
    fold_id TEXT NOT NULL,
    partition TEXT NOT NULL,
    val_score REAL,
    test_score REAL,
    train_score REAL,
    metric TEXT NOT NULL,
    task_type TEXT NOT NULL,
    n_samples INTEGER,
    n_features INTEGER,
    scores TEXT,
    best_params TEXT,
    branch_id INTEGER,
    branch_name TEXT
);

CREATE TABLE prediction_arrays (
    prediction_id TEXT PRIMARY KEY,
    y_true TEXT,
    y_pred TEXT,
    y_proba TEXT,
    sample_indices TEXT,
    weights TEXT
);

INSERT INTO projects (project_id, name, description, color)
VALUES ('project-real-golden', 'Real golden legacy fixtures', 'Reduced legacy workspace examples', '#14b8a6');

INSERT INTO runs (run_id, name, config, datasets, status, project_id)
VALUES (
    'run-old-2024',
    'legacy workspace export 2024',
    '{"cv":"group-kfold","random_state":17}',
    '[{"name":"corn-lot-2024"},{"name":"field/block 7"}]',
    'completed',
    'project-real-golden'
);

INSERT INTO pipelines (
    pipeline_id, run_id, name, expanded_config, generator_choices, dataset_name, dataset_hash,
    status, best_val, best_test, metric
)
VALUES (
    'pipe-old-pls',
    'run-old-2024',
    'PLS regression old pipeline',
    '{"steps":["snv","pls"]}',
    '[{"n_components":8}]',
    'corn-lot-2024',
    'sha256:corn-lot',
    'completed',
    0.12,
    0.15,
    'rmse'
), (
    'pipe-old-svm',
    'run-old-2024',
    'SVC classification old pipeline',
    '{"steps":["msc","svc"]}',
    '[{"C":4}]',
    'field/block 7',
    'sha256:block-7',
    'completed',
    0.75,
    0.70,
    'accuracy'
);

INSERT INTO chains (
    chain_id, pipeline_id, steps, model_step_idx, model_class, preprocessings, model_name,
    metric, task_type, best_params, dataset_name
)
VALUES (
    'chain-old-pls',
    'pipe-old-pls',
    '[{"name":"SNV"},{"name":"PLSRegression"}]',
    1,
    'sklearn.cross_decomposition.PLSRegression',
    'SNV',
    'PLSRegression',
    'rmse',
    'regression',
    '{"n_components":8}',
    'corn-lot-2024'
), (
    'chain-old-svm',
    'pipe-old-svm',
    '[{"name":"MSC"},{"name":"SVC"}]',
    1,
    'sklearn.svm.SVC',
    'MSC',
    'SVC',
    'accuracy',
    'classification',
    '{"C":4}',
    'field/block 7'
);

INSERT INTO predictions (
    prediction_id, pipeline_id, chain_id, dataset_name, model_name, model_class,
    fold_id, partition, val_score, test_score, train_score, metric, task_type,
    n_samples, n_features, scores, best_params, branch_id, branch_name
)
VALUES (
    'pred-old-pls-val',
    'pipe-old-pls',
    'chain-old-pls',
    'corn-lot-2024',
    'PLSRegression',
    'sklearn.cross_decomposition.PLSRegression',
    'fold-1',
    'validation',
    0.12,
    0.15,
    0.09,
    'rmse',
    'regression',
    3,
    128,
    '{"validation":{"rmse":0.12},"test":{"rmse":0.15}}',
    '{"n_components":8}',
    0,
    'legacy-main'
), (
    'pred-old-svm-test',
    'pipe-old-svm',
    'chain-old-svm',
    'field/block 7',
    'SVC',
    'sklearn.svm.SVC',
    'fold-2',
    'test',
    0.75,
    0.70,
    0.82,
    'accuracy',
    'classification',
    4,
    96,
    '{"validation":{"accuracy":0.75},"test":{"accuracy":0.70}}',
    '{"C":4}',
    0,
    'legacy-main'
);

INSERT INTO prediction_arrays (prediction_id, y_true, y_pred, y_proba, sample_indices, weights)
VALUES (
    'pred-old-pls-val',
    '[32.1,31.5,30.8]',
    '[32.0,31.4,31.0]',
    NULL,
    '[101,102,103]',
    '[1.0,0.8,1.2]'
), (
    'pred-old-svm-test',
    '[0,1,1,0]',
    '[0,1,0,0]',
    '[[0.9,0.1],[0.2,0.8],[0.6,0.4],[0.8,0.2]]',
    '[201,202,203,204]',
    NULL
);

PRAGMA user_version = 2;
COMMIT;
