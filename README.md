EggNest Reward V6 SSV backend.

This verifies Google AdMob Rewarded SSV signatures before adding in-app points,
and rejects duplicate transaction IDs.

Important: AdMob rewarded-ad rewards must remain non-monetary/non-transferable
and usable inside the publisher's platform/app. Do not convert these ad rewards
directly into cash, cryptocurrency, or gift cards.

Termux:
  cd ~/storage/downloads/EggNest_Reward_V6
  pip install -r requirements.txt
  export ADMOB_REWARDED_AD_UNIT="YOUR_AD_UNIT_ID"
  export ADMOB_REWARD_ITEM="coins"
  export ADMOB_REWARD_AMOUNT="10"
  python app.py

Real SSV callbacks require a public HTTPS deployment. 127.0.0.1 is local only.
Never put Telegram bot tokens or payment credentials in this project.
