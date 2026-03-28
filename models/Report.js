const mongoose = require('mongoose');
function haversineMeters(lat1,lng1,lat2,lng2){const R=6371000,r=Math.PI/180,dLat=(lat2-lat1)*r,dLng=(lng2-lng1)*r,a=Math.sin(dLat/2)**2+Math.cos(lat1*r)*Math.cos(lat2*r)*Math.sin(dLng/2)**2;return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));}
const VALID_TYPES=['crack','flood','light','tree','sign','sidewalk','graffiti','waste'];
const ReportSchema=new mongoose.Schema({
  type:{type:String,enum:VALID_TYPES,required:true,trim:true},
  title:{type:String,required:true,trim:true,minlength:5,maxlength:100},
  desc:{type:String,trim:true,maxlength:1000,default:''},
  location:{type:{type:String,enum:['Point'],default:'Point'},coordinates:{type:[Number],required:true}},
  lat:{type:Number,required:true},
  lng:{type:Number,required:true},
  votes:{type:Number,default:0,min:0},
  voterIps:{type:[String],select:false,default:[]},
  status:{type:String,enum:['active','resolved'],default:'active',index:true},
  resolvedAt:{type:Date,default:null},
  images:[{url:{type:String,required:true},publicId:{type:String,default:null},width:Number,height:Number,sizeKb:Number}],
  reporterIp:{type:String,select:false,required:true},
  isDuplicate:{type:Boolean,default:false},
},{timestamps:true,toJSON:{virtuals:true,transform(doc,ret){delete ret.reporterIp;delete ret.voterIps;delete ret.__v;return ret;}}});
ReportSchema.index({location:'2dsphere'});
ReportSchema.index({status:1,votes:-1});
ReportSchema.index({createdAt:-1});
ReportSchema.statics.findNearby=function(lat,lng,radiusMeters=20){return this.find({status:'active',location:{$nearSphere:{$geometry:{type:'Point',coordinates:[lng,lat]},$maxDistance:radiusMeters}}}).select('_id title type votes lat lng');};
ReportSchema.methods.distanceTo=function(lat,lng){return haversineMeters(this.lat,this.lng,lat,lng);};
module.exports=mongoose.model('Report',ReportSchema);
