#!/bin/bash
#================================================================================
#       *** Company Confidential Information -- Do Not Redistribute ***
#
# 	Author: Tony La
# 	Date: 20170614
#
#	File: sg-security.sh
#
#   	Objective:  Deny change to security group with public subnet EC2 instances
#
#	Requirement: AWS CLI and profile setup ~/.aws/credentials
#
#	Usage: sg-security.sh <profile-name>
#
# 	Description: This script create a group called "SG-security" and assign it to all non-admin users.  
#	SG-security group contains one policy which deny changes to any security group with tag, 
#	"key:IsPublicSG Value:PublicFacingSG".
#
#================================================================================
#
#
function tag-sg-with-public-subnet-ec2 {
    aws ec2 describe-instances \
      --profile=$AWS_ACCOUNT --region=us-east-1 \
      --filters \
          "Name=instance-state-name,Values=running" \
      --query 'Reservations[].Instances[].[ [Tags[?Key==`Name`]. Value][0][0],
          SubnetId,PrivateIpAddress,KeyName,InstanceId,PublicIpAddress,SecurityGroups[].GroupName[]]' \
      --output text > servers-$AWS_ACCOUNT
    vpc_temp=`aws ec2 describe-subnets --profile=$AWS_ACCOUNT --region=us-east-1|grep VpcId|\
      awk -F":" '{print $2}'| awk -F"," '{print $AWS_ACCOUNT}'|sort|uniq|grep -v \"\"|\
      sed -e 's/^"//' -e 's/"$//'|awk -F"\"" '{print $2}'`
    # find all subnet with vpc as input
    for i in `echo $vpc_temp`
    do
      subnet_temp=`aws ec2 describe-subnets --filters "Name=vpc-id,Values=$i" --profile=$AWS_ACCOUNT --region=us-east-1|\
        grep SubnetId|awk -F":" '{print $2}'|awk -F"," '{print $AWS_ACCOUNT}'|sort|uniq|grep -v \"\"|\
        sed -e 's/^"//' -e 's/"$//'|awk -F"\"" '{print $2}'`
      for j in `echo $subnet_temp`
      do
        aws ec2 describe-route-tables --filters --filters "Name=association.subnet-id,Values=$j" \
          --profile=$AWS_ACCOUNT --region=us-east-1 |egrep -i -q igw
        if [ $? -eq 0 ];
          then
            instanceid_temp=`egrep $j servers-$AWS_ACCOUNT|awk '{print $5}'`
            for k in `echo $instanceid_temp`
              do
                sgid=`aws ec2 describe-instances --profile=$AWS_ACCOUNT --region=us-east-1 --instance-ids $k|\
                  grep GroupId|awk '{print $NF}'|grep -v default|awk -F"," '{print $AWS_ACCOUNT}'|sort|uniq|\
                  grep -v \"\"| sed -e 's/^"//' -e 's/"$//'`
                aws ec2 describe-security-groups --group-ids $sgid --profile=$AWS_ACCOUNT --region=us-east-1|\
                  egrep -q IsPublicSG && echo "$sgid already tagged" || (echo $sgid not tag yet..now tagging; \
                  aws ec2 create-tags --profile=$AWS_ACCOUNT --region=us-east-1 --resources $sgid \
                  --tags Key=IsPublicSG,Value=PublicFacingSG)
          done
        fi
      done
    done
    echo "=============="
}

#
function create-iam-role-group {
    # check and create group/policy
    aws iam list-groups --profile=$AWS_ACCOUNT |egrep -q SG-Security 
    if [ $? -eq 0 ];then
        echo "group SG-Security exist. no need to create" 
    else
        echo "group SG-Security does not exist - now creating SG-Security"
        aws iam create-group --group-name SG-Security --profile=$AWS_ACCOUNT;aws iam put-group-policy \
          --group-name SG-Security --policy-document file://SG-Security.json --policy-name SG-Security \
          --profile=$AWS_ACCOUNT
    fi
   echo "============="
}
#


# assign user to SG-Security group to prevent change to public facing security group
function assign-non-admin-user-to-group {
    # list all users
    all_user=`aws iam list-users --profile=$AWS_ACCOUNT --region=us-east-1|grep UserName|awk -F":" \
      '{print $2}'|awk -F"," '{print $AWS_ACCOUNT}'|sort|uniq|grep -v \"\"| sed -e 's/^"//' -e 's/"$//'|\
      awk -F"\"" '{print $2}'`
    for i in `echo $all_user`
    do
      user_temp=`aws iam list-groups-for-user --user-name $i --profile=$AWS_ACCOUNT --region=us-east-1`
      # check if user already has SG-Security group
      echo $user_temp | egrep -q admins
      if [ $? -eq 0 ]
        then
          echo $i is admin - no need to assign group
      else
        echo $user_temp |egrep -q SG-Security 
        if [ $? -eq 0 ];then
          echo $i already belong to group SG-Security 
        else
          echo $i not in SG-Security group...now assigning $i to SG-Security
          aws iam add-user-to-group --user-name $i --group-name SG-Security --profile=$AWS_ACCOUNT --region=us-east-1
        fi
      fi
      echo "============="
    done
    # remove temp files
    rm SG-Security.json > /dev/null 2>&1
    rm servers-$AWS_ACCOUNT > /dev/null 2>&1
}
#
#
# Main
echo "running $0 on $AWS_ACCOUNT AWS"
echo "================================================================================"
echo " "
#
tag-sg-with-public-subnet-ec2 $AWS_ACCOUNT
create-iam-role-group $AWS_ACCOUNT
assign-non-admin-user-to-group $AWS_ACCOUNT
