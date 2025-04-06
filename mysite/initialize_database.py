#!/usr/bin/env python3

import sqlite3
import os

db = \
"""
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    password TEXT,
    blog TEXT
);
INSERT INTO Users (name,password,blog) VALUES('Kuba','password','The text of my blog');
INSERT INTO Users (name,password,blog) VALUES('Gecko','password','Gex, havent written anything');
INSERT INTO Users (name,password,blog) VALUES('Robocod','password','James Pond');
INSERT INTO Users (name,password,blog) VALUES('Fox','password','Sasha Nein');
INSERT INTO Users (name,password,blog) VALUES('Riddle','password','Voldemort');
COMMIT;
"""

if os.path.exists('bloggify.sqlite'):
	print('bloggify.sqlite exists')
else:
	conn = sqlite3.connect('bloggify.sqlite')
	conn.cursor().executescript(db)
	conn.commit()

import sqlite3
import os

db = \
"""
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    password TEXT,
    blog TEXT
);
INSERT INTO Users (name,password,blog) VALUES('Kuba','password','The text of my blog');
INSERT INTO Users (name,password,blog) VALUES('Gecko','password','Gex, havent written anything');
INSERT INTO Users (name,password,blog) VALUES('Robocod',password','James Pond');
INSERT INTO Users (name,password,blog) VALUES('Fox','password','Sasha Nein');
INSERT INTO Users (name,password,blog) VALUES('Riddle','password','Voldemort');
COMMIT;
"""

if os.path.exists('bloggify.sqlite'):
	print('bloggify.sqlite exists')
else:
	conn = sqlite3.connect('bloggify.sqlite')
	conn.cursor().executescript(db)
	conn.commit()
