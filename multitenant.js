var mongo = require('mongoskin');
var bcrypt = require('bcrypt');
var ObjectID = require('mongodb').ObjectID;
var _ = require('lodash');

module['exports'] = function(Hyperyun, app, config) {
	var company = config.company;
	var companyCapitalized = config.companyCapitalized;
	// Not used
	var companyApp = config.companyApp;
	var companyURL = config.url;

	var dlim = config.dlim;

	var multiUri = config.database.split('/');
	multiUri.pop();
	multiUri = multiUri.join("/")+"/baas";
	var multiDb = mongo.db(multiUri, {safe: false});
	console.log("Connecting to MongoDB for Multitenant: "+multiUri);

	app.post('/adminapi/hasemail', function(req, res) {
		multiDb.collection('users').findOne({email: req.body.email}, function(err, email) {
		  res.json({err: err, res: email?true:false});
		});
	});

	app.post('/adminapi/hasapp', function(req, res) {
		multiDb.collection('applications').findOne({url: req.body.url}, function(err, app) {
		  res.json({err: err, res: app?true:false});
		});
	});

	app.post('/adminapi/apps', function(req, res) {
		multiDb.collection('users').findOne({loginToken: req.body.loginToken}, function(err, user) {
		  res.json(user.apps);
		});
	});

	app.post('/adminapi/login', function(req, res) {
		Hyperyun.Multitenant.login(req.body.login, function(obj) {
		  res.json(obj);
		});
	});

	app.post('/adminapi/logintoken', function(req, res) {
		multiDb.collection('users').findOne({"loginToken.token": req.body.token}, function(err,doc){
			if(!err && doc) res.json({err: false, res: doc});
			else res.json({err: err, res: false});
		});
	});

	app.post('/adminapi/createapp', function(req, res) {
		Hyperyun.Multitenant.testData(req.body.user, req.body.app, function(test) {
			if(!test.err) {
				Hyperyun.Multitenant.createApplication(req.body.user, req.body.app, function(obj) {
					res.json(obj);
				});
			} else {
				res.json({err: test.err, res: false});
			}
		});
	});

	app.post('/adminapi/addapp', function(req, res) {
		if(!req.body.token || !req.body.app || !req.body.app.name || !req.body.app.url) {
			res.json({err: "Data missing", res: false});
		} else {
			multiDb.collection('users').findOne({"loginToken.token": req.body.token}, function(err, user) {
				if(!err && user) {
					var app = req.body.app;
					app.owner = {email: user.email, _id: user._id};
					Hyperyun.Multitenant.makeApp(app, function(obj) {
						res.json(obj);
					});
				} else {
					res.json({err: "Invalid Token", res: false});
				}
			});
		}
	});


	Hyperyun.Multitenant = {};

	Hyperyun.Multitenant.testData = function(user, app, callback) {
		var error = false;
		var validmail = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
		var validappurl = /^[a-zA-Z0-9_]+$/;
		if(!user.password || !user.email || !app.url) {
			error = companyCapitalized+": Error: Data missing.";
		} else if(!validmail.test(user.email)) {
			error = companyCapitalized+": Invalid Email.";
		} else if(!validappurl.test(app.url)) {
			error = companyCapitalized+": Invalid App URL.";
		} 
		if(!error){
			multiDb.collection('users').findOne({email: user.email}, function(err, usermail){
				if(!usermail) {
					multiDb.collection('applications').findOne({url: app.url}, function(err, appurl){
						if(!appurl) {
							callback({err: null});
						} else {
							callback({err: companyCapitalized+": App exists"});
						}
					});		
				} else {
					callback({err: companyCapitalized+": Email exists"});
				}
			});
		} else {
			callback({err: error});
		}
	}

	Hyperyun.Multitenant.login = function(data, callback) {
		multiDb.collection('users').findOne({email: data.email}, function(err,doc){
			if(doc){
				if (doc.status) {
					bcrypt.compare(data.password, doc.password, function(err, test) {
					   if(test) {
							var enddate=new Date()
							enddate.setDate(enddate.getDate() + 6);
							var token = bcrypt.hashSync(doc._id+new Date(), bcrypt.genSaltSync(10));
							var modifier = {$set: {isOnline:true, lastLoggedIn:new Date(),loginToken: {token: token, expires: enddate}}};
							multiDb.collection('users').update({email: data.email}, modifier, {}, function(err, sth){
								if(!err) {
									doc.loginToken = {token: token, expires: enddate};
									delete doc.password;
									Hyperyun.Multitenant.copyLoginToken(data.email, doc.apps, doc.loginToken);
									callback({err: err, res: doc});
								} else callback({err: companyCapitalized+": Error: Incorrect password.", res: undefined});
							});
						} else callback({err: companyCapitalized+": Error: Something went wrong.", res: undefined});
					});
				} else callback({err: companyCapitalized+": Error: Account not activated yet.", res: undefined});
			} else callback({err: companyCapitalized+": Error: unable to find doc to log in to. Target account does not exist", res: false});
		});
	}

	Hyperyun.Multitenant.copyLoginToken = function(email, apps, logintoken) {
		_.each(apps, function(app) {
			Hyperyun.Hyperstore.makeCollection(app.url+dlim+company+"Admins");
			Hyperyun.Hyperstore.collections[app.url+dlim+company+"Admins"].db.update({emails: {$in: [email]}}, {$set: {loginToken: logintoken}}, function(e, r) {
				console.log({err: e, app: app.url});
				console.log({q: {emails: {$in: [email]}}, mod: {$set: {loginToken: logintoken}}});
			});
		});
	}

	Hyperyun.Multitenant.activate = function(code, callback) {
		multiDb.collection('users').findOne({activate: code}, function(err,user){
			if(user && code.length>3){
				multiDb.collection('users').update({email: user.email}, {$set: {activate: 1, status: 1}}, function(err, sth){
					if(!err) {
						Hyperyun.Multitenant.activateAdmins(user.email, user.apps);
						Hyperyun.Mailer.sendMailAdmin(user, "Activation", function(err, sth) {
							if(err) callback({err: companyCapitalized+": Error: Faild to send mail.", res: false})
							else callback({err: false, res: true});
						});
					} else callback({err: companyCapitalized+": Error: Update went wrong.", res: undefined});
				});
			} else callback({err: companyCapitalized+": Error: Wrong code", res: false});
		});
	}

	Hyperyun.Multitenant.activateAdmins = function(email, apps) {
		_.each(apps, function(app) {
			Hyperyun.Hyperstore.makeCollection(app.url+dlim+company+"Admins");
			Hyperyun.Hyperstore.collections[app.url+dlim+company+"Admins"].db.update({emails: {$in: [email]}}, {$set: {activate: 1, status: 1}}, function(e, r) {
				console.log({err: e, app: app.url});
				console.log(email);
			});
		});
	}

	Hyperyun.Multitenant.createApplication = function(user, app, callback) {
		Hyperyun.Multitenant.addUser(user, app, function(newUser, err) {
			if(newUser && !err) {
				var appData = app;
				appData.owner = user;
				delete appData.owner.password;
				appData.owner._id = newUser._id;
		
				multiDb.collection('applications').insert(appData, function(err, newApp) {
					var mailUser = {emails: [user.email]};
					app.user = newUser;
					Hyperyun.Multitenant.makeApp(app, function(obj) {
						Hyperyun.Mailer.sendMailAdmin(newUser, "Registration", function(err, sth) {
							if(err) callback({err: companyCapitalized+": Error: Faild to send mail.", res: false})
							else callback(obj);
						});
					});
					//if(!err) Hyperyun.Mailer.sendMail(app.url, "Registration", mailUser, void(0), function(e, res) {
						
					//}, true);
				});					
			} else {
				callback({err: err, res: false})
			}
		});
	};

	Hyperyun.Multitenant.addUser = function(user, app, callback) {
		var loginToken = null;
		var pass = null;
		var services = new Object();
		var newUserData = {
			email : user.email,
			apps: [app],
			createdAt : new Date(),
			profile : (user.profile ? user.profile : null),
			role: 'Member',
			services : services,
			status : 0,
			loginToken : null,
			modifiedAt : new Date(),
		}

		var salt = bcrypt.genSaltSync(10);
		newUserData.password = bcrypt.hashSync(user.password, salt);
		newUserData.activate = new ObjectID().toHexString();
		
		multiDb.collection('users').insert(newUserData, {safe: true}, function(err, doc){
			console.log(newUserData);
			console.log({safe: true});
			console.log(err);
			console.log(doc);
			var createdUser = doc[0];
			delete createdUser.password;
			callback(createdUser, err);
		});
	};

	Hyperyun.Multitenant.populateAdmins = function(application, callback) {
		//Populate _hyperyunAdmins table
		multiDb.collection('users').find({$or:[{role:"Admin"},{_id: application.user._id}]}).toArray(function(err,admins){
			_.forEach(admins,function(user){
				Hyperyun.Accounts.createOrUpdateAccount('password', {user: user, appName: application.url}, function(err,firstUser){
					if(err && !err.err){
						console.log("Added",firstUser,"as a member of",application.url)
					} else {
						console.log("WAS UNABLE TO ADD",application.firstUser,"as a member of",application.name,":",err);
					}
				}, true);
			});
			callback({err: err, res: true});
		});
	}

	Hyperyun.Multitenant.makeApp = function(application, callback){
		if(!application.name || !application.url) {
			callback({err: companyCapitalized+": Error: Need to provide both a name and a url for the new application ("+application.name+","+application.url+")", res: null});
		} else {
			Hyperyun.Hyperstore.makeCollection(application.url+dlim+company+"Configuration");
			Hyperyun.Hyperstore.collections[application.url+dlim+company+"Configuration"].db.findOne({url: application.url}, function(err, app){
				if(!app) {
					Hyperyun.Application.generateNewAppJson(application.name, application.url, application.user, function(json) {
						Hyperyun.Hyperstore.makeCollection(application.url+dlim+company+"Collections");
						Hyperyun.Hyperstore.makeCollection(application.url+dlim+company+"Admins");
						var collection = application.url+dlim+company+"Configuration";
						Hyperyun.Hyperstore.makeCollection(application.url+dlim+company+"Configuration");
						Hyperyun.Hyperstore.collections[collection].db.insert(json, function(err, doc){
							if(err) {
								console.log("ERROR while inserting configuration object:",err)
								callback({err: err, res: false});
							} else {
								//Initialize collections table
								//TODO: revisit callbacks here
								Hyperyun.Hyperstore.collections[application.url+dlim+company+"Collections"].db.insert({name:"users"},function(){});
								Hyperyun.Hyperstore.collections[application.url+dlim+company+"Collections"].db.insert({name:"files"},function(){});
								_.forEach(
									_.map(Hyperyun.constants.companyColls,function(v,k){return {full:application.app+dlim+v,part:v}}),//create {'foo_collection','collection'} pairs
									function(v){Hyperyun.Hyperstore.collections[application.url+dlim+company+"Collections"].db.insert({name:v.part},function(){})}
								); //init each collection with a name

								Hyperyun.Multitenant.populateAdmins(application, function(o) {
									callback(o);
								});
							}
						});
					});
				} else {
					callback({err: companyCapitalized+": Error: Application exists at this address ("+application.url+")->"+JSON.stringify(app), res:null});
				}
			});
		}
	};

	Hyperyun.Multitenant.permanentlyDeleteScheduledApplications = function(callback)
	{
		var collection = companyApp+dlim+"appsToDelete";
		Hyperyun.Hyperstore.makeCollection(collection);
		Hyperyun.Hyperstore.collections[collection].db.find({scheduledForDeletionAt: {$exists: true}}).toArray(function(err, apps){
			if(err || !apps){
				callback(err);
			} else {
				for(var i = 0; i < _.size(apps); i ++)
				{
					var app = apps[i];
					var appName = app.url;
					Hyperyun.Utils.togglelog("App scheduled for deletion at " + app.scheduledForDeletionAt,'appDeletion');
					if(new Date(app.scheduledForDeletionAt).getTime() < new Date().getTime())
					{
						Hyperyun.Utils.togglelog("PROCEEDING TO DELETE "+appName,'appDeletion');
						var fileCollection = appName + dlim+"files";
						Hyperyun.Hyperstore.makeCollection(fileCollection);
						Hyperyun.Hyperstore.collections[fileCollection].db.find({}).toArray(function(err, allFiles){
							if(allFiles && !err)
							{
								Hyperyun.Utils.togglelog("All files : " + _.size(allFiles),'appDeletion');
								for(var i = 0; i < _.size(allFiles); i ++)
								{
									if(allFiles[i]._id)
										gfs.remove({_id:allFiles[i]._id},function(a,b,c){Hyperyun.Utils.togglelog("Deleted " + allFiles[i]._id,'appDeletion')});
								}
								Hyperyun.Hyperstore.collections[appName+dlim+company+"Collections"].db.find({}).toArray(function(err,allColls){
									if(err || !allColls)
									{
										console.error("error while deleting application",err,allcolls)
										return;
									}
									_.forEach(allColls,function(coll){
										if(coll.name)
										{
											Hyperyun.Hyperstore.makeCollection(appName+dlim+coll.name);
											Hyperyun.Hyperstore.collections[appName+dlim+coll.name].db.drop();
											Hyperyun.Utils.togglelog("Deleted db collection " + collForDeletion,'appDeletion');
										}
									})
								})
								Hyperyun.Hyperstore.collections[collection].db.remove({url: appName}, function(err){
									if(err) callback({res:true,err:err,info:{version:new Date()}});
									else
										{
											Hyperyun.Utils.togglelog("Deleted application "+appName,'appDeletion');
											if(callback)callback({res:false,err:null,info:{version:new Date()}});
										}
								})
							} else Hyperyun.Utils.togglelog("Failed to get file data: "+ e,'appDeletion');
						})
					}
					else
					{
						Hyperyun.Utils.togglelog("App deletion scheduled for later: skipping "+app.url + " until " + app.scheduledForDeletionAt,'appDeletion');
					}
				}
			}
		});
	}
	Hyperyun.Multitenant.scheduleApplicationDeletion = function(access, callback)
	{
		var deleteDate = new Date();
		deleteDate.setMonth(deleteDate.getMonth()+1);
		var collection = access.app + dlim + company + "Configuration";
		var appName = access.app;
		Hyperyun.Hyperstore.makeCollection(collection);
		var sel = {url: appName};
		var mod = {$unset: {scheduledForDeletionAt: deleteDate}};
		var tsid = 0;
		var opt = {};
		Hyperyun.Hyperstore.makeCollection(companyApp+dlim+"appsToDelete");
		Hyperyun.Hyperstore.collections[companyApp+dlim+"appsToDelete"].db.update({url:appName}, {$set:{scheduledForDeletionAt: deleteDate}},{upsert:true},function(){});
		Hyperyun.Hyperstore.collections[collection].db.update({url: appName}, {$set: {scheduledForDeletionAt: deleteDate}}, function(err, app){
			if(!err){
				io.of("/"+collection).emit('getUpdate', {
					version: Hyperyun.Hyperstore.collections[collection].version,
					sel: sel,
					mod: mod,
					options: opt,
					socketid: tsid});
				if(callback)callback({res: deleteDate, err: null, info:{version: new Date()}});
			} else if(callback) callback({res:false, err: err, info:{version: new Date()}});
		});
	}
	Hyperyun.Multitenant.cancelApplicationDeletion = function(access, callback)
	{
		var collection = access.app+dlim+company+"Configuration";
		var appName = access.app;
		Hyperyun.Hyperstore.makeCollection(collection);
		var sel = {url: appName};
		var mod = {$unset: {scheduledForDeletionAt: ""}};
		var tsid = 0;
		var opt = {};
		Hyperyun.Hyperstore.makeCollection(companyApp+dlim+"appsToDelete");
		Hyperyun.Hyperstore.collections[companyApp+dlim+"appsToDelete"].db.remove({url:appName},function(){});
		Hyperyun.Hyperstore.collections[collection].db.update(sel, mod, function(err, app){
			if(!err){
				io.of("/"+collection).emit('getUpdate', {
					version: Hyperyun.Hyperstore.collections[collection].version,
					sel: sel,
					mod: mod,
					options: opt,
					socketid: tsid});
				if(callback) callback({res:true, err: null, info:{version: new Date()}});
			} else if(callback) callback({res: false, err: err, info:{version: new Date()}});
		});
	}
}